#!/usr/bin/env python3
# =============================================================================
# gnn_baseline.py ── 圖資料集的 GNN baseline（單類異常偵測）
# =============================================================================
# 方法學（與 ml/ 和 net/ 的既有管線一致，不可退步）：
#   1. **只用 benign 訓練**（單類/無監督）。攻擊場景完全不參與訓練，
#      也不參與標準化的 fit —— 否則測試分布資訊會洩漏。
#   2. **多 seed 報 mean ± std**。舊實驗的教訓：單次執行的 F1 可能純粹是雜訊
#      （見 ml/EXPERIMENTS_V2.md，DeepLog 的 F1 std 比 mean 還大）。
#   3. **不用 accuracy**。異常僅 0.49%，全猜正常就有 99.5%。報 PR-AUC / F1 / FPR。
#
# ⚠️ 關於 log 特徵的洩漏風險（本腳本的核心設計決定）：
#   節點特徵裡的 `log_lines_null` 是「該秒有幾行匿名寫入」。實測單用
#   `log_lines_null > 0` 這**一條規則**就有 precision=1.000 / recall=0.750。
#   若把它餵給 GNN，模型只會去背這個欄位 —— 那等於用 GNN 重新學一遍
#   ml/EXPERIMENTS_V2.md 已經驗證過的 SourceNode 規則，得不到任何新資訊。
#
#   因此本腳本訓練**兩個變體**：
#     net_only : 只用網路層特徵（7 維）→ **這才是真正的問題**：
#                「光看流量結構，能不能偵測到攻擊？」
#     net+log  : 加上 log 特徵（9 維）→ 上界對照，預期會很高但意義有限。
#
# 模型：GraphSAGE encoder + 全圖 pooling → 單類異常分數。
#   訓練目標用 benign 的重建誤差（autoencoder 式），推論時誤差大 = 異常。
#   刻意選簡單架構：本資料每張圖只有約 10 個節點，複雜模型只會過擬合。
#
# 執行： ml/venv/bin/python net/gnn_baseline.py <capture_dir>
# 輸出： <capture_dir>/graph/gnn_results.txt
# =============================================================================
import os, sys, json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from torch_geometric.nn import SAGEConv, global_mean_pool, global_max_pool
from sklearn.metrics import (precision_recall_fscore_support,
                             average_precision_score, roc_auc_score)

NET_FEATS = ["n_pkts", "bytes_c2s", "bytes_s2c", "n_syn",
             "n_finrst", "max_payload", "degree"]
LOG_FEATS = ["log_lines_named", "log_lines_null"]
EDGE_FEATS = ["n_pkts", "n_c2s", "n_s2c", "bytes_c2s",
              "bytes_s2c", "n_syn", "n_finrst", "max_payload"]
SEEDS = [42, 43, 44, 45, 46]
EPOCHS, HIDDEN, LR = 30, 32, 1e-3

log = []
def out(s=""):
    print(s); log.append(str(s))


# =============================================================================
# 資料
# =============================================================================
def load_graphs(gdir, feats):
    nodes = pd.read_csv(os.path.join(gdir, "nodes.csv"))
    edges = pd.read_csv(os.path.join(gdir, "edges.csv"))
    graphs = pd.read_csv(os.path.join(gdir, "graphs.csv"))

    # 依 (scenario, sec) 分組，避免逐圖 filter 造成 O(n²)
    ng = {k: v for k, v in nodes.groupby(["scenario", "sec"])}
    eg = {k: v for k, v in edges.groupby(["scenario", "sec"])}

    items = []
    for r in graphs.itertuples():
        key = (r.scenario, r.sec)
        n = ng.get(key)
        if n is None or len(n) == 0:
            continue
        n = n.reset_index(drop=True)
        e = eg.get(key)
        idx = {nm: i for i, nm in enumerate(n.node)}
        if e is None or len(e) == 0:
            ei = torch.empty((2, 0), dtype=torch.long)
            ea = torch.empty((0, len(EDGE_FEATS)), dtype=torch.float)
        else:
            src = [idx[s] for s in e.src if s in idx]
            dst = [idx[d] for d in e.dst if d in idx]
            if len(src) != len(e) or len(dst) != len(e):
                continue                     # 端點缺漏 → 跳過（實測為 0 筆）
            # 無向圖：兩個方向都加，讓訊息能雙向傳遞
            ei = torch.tensor([src + dst, dst + src], dtype=torch.long)
            ea = torch.tensor(np.vstack([e[EDGE_FEATS].values,
                                         e[EDGE_FEATS].values]), dtype=torch.float)
        items.append(dict(
            scenario=r.scenario, sec=r.sec,
            x=torch.tensor(n[feats].values, dtype=torch.float),
            edge_index=ei, edge_attr=ea,
            y=int(r.label),
        ))
    return items


def standardize(items, train_idx):
    """只用訓練集（benign）fit 標準化參數 —— 避免測試分布洩漏。"""
    tr = torch.cat([items[i]["x"] for i in train_idx], dim=0)
    mu, sd = tr.mean(0), tr.std(0)
    sd[sd == 0] = 1.0
    for it in items:
        it["x"] = (it["x"] - mu) / sd
    return mu, sd


def to_data(it):
    return Data(x=it["x"], edge_index=it["edge_index"],
                edge_attr=it["edge_attr"], y=torch.tensor([it["y"]]))


# =============================================================================
# 模型：GraphSAGE encoder → pooling → decoder（重建 pooled 表示）
# =============================================================================
class GraphAE(nn.Module):
    """單類異常偵測：學會重建 benign 的圖表示，異常圖重建誤差大。

    刻意用 mean+max 兩種 pooling 串接：
      mean 抓「整體流量水準」，max 抓「有沒有某個節點特別突出」。
      攻擊的特徵正是後者（多出一個行為異常的節點）。
    """
    def __init__(self, in_dim, hid=HIDDEN):
        super().__init__()
        self.c1 = SAGEConv(in_dim, hid)
        self.c2 = SAGEConv(hid, hid)
        self.dec = nn.Sequential(
            nn.Linear(hid * 2, hid), nn.ReLU(), nn.Linear(hid, hid * 2))

    def forward(self, d):
        h = torch.relu(self.c1(d.x, d.edge_index))
        h = torch.relu(self.c2(h, d.edge_index))
        g = torch.cat([global_mean_pool(h, d.batch),
                       global_max_pool(h, d.batch)], dim=1)
        return g, self.dec(g)


def run_seed(items, train_idx, test_idx, in_dim, seed):
    torch.manual_seed(seed); np.random.seed(seed)
    model = GraphAE(in_dim)
    opt = torch.optim.Adam(model.parameters(), lr=LR)

    tr_loader = DataLoader([to_data(items[i]) for i in train_idx],
                           batch_size=64, shuffle=True)
    model.train()
    for _ in range(EPOCHS):
        for b in tr_loader:
            opt.zero_grad()
            g, rec = model(b)
            loss = ((rec - g.detach()) ** 2).mean()
            loss.backward(); opt.step()

    model.eval()
    te_loader = DataLoader([to_data(items[i]) for i in test_idx],
                           batch_size=256, shuffle=False)
    scores = []
    with torch.no_grad():
        for b in te_loader:
            g, rec = model(b)
            scores.append(((rec - g) ** 2).mean(dim=1))
    return torch.cat(scores).numpy()


def evaluate(scores, y_true):
    """報「與門檻無關」的 PR-AUC/ROC-AUC，外加兩個明確定義的工作點。

    ⚠️ 踩過的坑：一開始把門檻寫死在 99 分位，但測試集異常比例是 0.79%
    —— 99 分位會標記 1%（約 30 張），而真異常只有 24 張，**就算排序完美
    precision 上限也只有 78.6%**，且 F1 被壓到接近 0，看起來像模型失效。
    門檻是取捨旋鈕，必須對齊資料的異常比例，不能寫死。

    兩個工作點：
      at_rate : 門檻取「異常比例」對應的分位數（= 假設已知異常量的理想部署）
      best_f1 : 掃過所有門檻取最佳 F1（= 該模型排序能力的上限）
    """
    y_true = np.asarray(y_true)
    nm = y_true == 0
    res = dict(
        pr_auc=float(average_precision_score(y_true, scores)),
        roc_auc=float(roc_auc_score(y_true, scores)) if len(set(y_true)) > 1 else float("nan"),
    )

    def point(pred):
        p, r, f, _ = precision_recall_fscore_support(
            y_true, pred, average="binary", zero_division=0)
        return (float(p), float(r), float(f),
                float(pred[nm].sum() / max(nm.sum(), 1)))

    rate = float(y_true.mean())
    thr = np.percentile(scores, 100 * (1 - rate))
    p, r, f, fpr = point((scores >= thr).astype(int))
    res.update(precision=p, recall=r, f1=f, fpr=fpr)

    best = (0.0, 0.0, 0.0, 0.0)
    for t in np.unique(scores):
        cand = point((scores >= t).astype(int))
        if cand[2] > best[2]:
            best = cand
    res.update(best_precision=best[0], best_recall=best[1],
               best_f1=best[2], best_fpr=best[3])
    return res


def run_variant(gdir, feats, title, note):
    out("\n" + "=" * 78)
    out(f"{title}（特徵 {len(feats)} 維）")
    out("=" * 78)
    out(note)

    items = load_graphs(gdir, feats)
    train_idx = [i for i, it in enumerate(items) if it["scenario"] == "benign"]
    test_idx = [i for i, it in enumerate(items) if it["scenario"] != "benign"]
    standardize(items, train_idx)

    y = np.array([items[i]["y"] for i in test_idx])
    out(f"訓練(benign) {len(train_idx)} 張 · 測試 {len(test_idx)} 張 · "
        f"測試異常 {int(y.sum())} ({y.mean():.2%})")

    runs = []
    for sd in SEEDS:
        sc = run_seed(items, train_idx, test_idx, len(feats), sd)
        m = evaluate(sc, y)
        runs.append(m)
        out(f"  seed={sd}  PR-AUC={m['pr_auc']:.3f} ROC-AUC={m['roc_auc']:.3f} | "
            f"@rate F1={m['f1']:.3f} | bestF1={m['best_f1']:.3f} "
            f"(P={m['best_precision']:.3f} R={m['best_recall']:.3f})")

    agg = {}
    out("\n  多 seed（mean ± std）:")
    for k in ["pr_auc", "roc_auc", "precision", "recall", "f1", "fpr",
              "best_precision", "best_recall", "best_f1"]:
        v = np.array([r[k] for r in runs], dtype=float)
        agg[k] = dict(mean=float(v.mean()), std=float(v.std()))
        out(f"    {k:<10} {v.mean():.3f} ± {v.std():.3f}")
    return agg


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: gnn_baseline.py <capture_dir>")
    root = os.path.abspath(sys.argv[1])
    gdir = os.path.join(root, "graph")
    if not os.path.exists(os.path.join(gdir, "nodes.csv")):
        sys.exit(f"找不到 {gdir}/nodes.csv —— 請先跑 build_graph.py")

    out("=" * 78)
    out("GNN baseline —— 單類異常偵測（只用 benign 訓練）")
    out("=" * 78)
    out(f"資料：{root}")
    out(f"模型：GraphSAGE(2層) + mean/max pooling + AE 重建誤差")
    out(f"seeds={SEEDS} · epochs={EPOCHS} · hidden={HIDDEN}")

    a = run_variant(
        gdir, NET_FEATS, "變體 A：net_only（只看網路層）",
        "⭐ 這是真正的問題：**光看流量結構**，能不能偵測到攻擊？\n"
        "   不含任何 log 欄位，模型無法走 SourceNode 的捷徑。")

    b = run_variant(
        gdir, NET_FEATS + LOG_FEATS, "變體 B：net+log（含應用層，上界對照）",
        "⚠️ log_lines_null 單獨一條規則就有 precision=1.000/recall=0.750，\n"
        "   模型很可能只是去背它 —— 高分不代表 GNN 學到了結構。")

    out("\n" + "=" * 78)
    out("解讀")
    out("=" * 78)
    out(f"net_only  PR-AUC = {a['pr_auc']['mean']:.3f} ± {a['pr_auc']['std']:.3f}")
    out(f"net+log   PR-AUC = {b['pr_auc']['mean']:.3f} ± {b['pr_auc']['std']:.3f}")
    out("")
    out("判讀原則（沿用本專案的方法學）：")
    out("- 若 std 接近或大於 mean → 結果由隨機初始化主導，**不可宣稱模型有效**。")
    out("- net+log 若明顯較高，多半是背下了 log_lines_null，")
    out("  那等於用 GNN 重學一遍已驗證的 SourceNode 規則，沒有新增價值。")
    out("- 真正有價值的訊號是 **net_only 明顯優於隨機**（PR-AUC >> 異常比例 0.005）。")

    with open(os.path.join(gdir, "gnn_results.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in log) + "\n")
    with open(os.path.join(gdir, "gnn_summary.json"), "w", encoding="utf-8") as f:
        json.dump(dict(net_only=a, net_log=b, seeds=SEEDS,
                       epochs=EPOCHS, hidden=HIDDEN), f, ensure_ascii=False, indent=2)
    print(f"\n報告已存: {gdir}/gnn_results.txt")


if __name__ == "__main__":
    main()
