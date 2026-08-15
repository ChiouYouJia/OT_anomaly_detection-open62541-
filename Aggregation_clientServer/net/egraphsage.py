#!/usr/bin/env python3
# =============================================================================
# egraphsage.py ── E-GraphSAGE 邊分類 NIDS（Lo et al., NOMS 2022）
# =============================================================================
# 論文：W.W. Lo, S. Layeghy, M. Sarhan, M. Gallagher, M. Portmann,
#       "E-GraphSAGE: A Graph Neural Network based Intrusion Detection System
#        for IoT", NOMS 2022. DOI: 10.1109/NOMS54207.2022.9789878
#
# 與原始 GraphSAGE 的三個關鍵差異（本檔忠實實作）：
#   Eq.4  鄰域聚合改成聚合**邊特徵**，而非鄰居節點嵌入：
#           h^k_N(v) = AGG_k({ e^{k-1}_uv , ∀u∈N(v), uv∈E })
#   Eq.2  節點更新照舊： h^k_v = σ( W^k · CONCAT(h^{k-1}_v , h^k_N(v)) )
#   Eq.5  邊嵌入 = 兩端節點嵌入的串接： z_uv = CONCAT(z_u , z_v)
#         → 對 z_uv 做 softmax 即為**邊分類**（flow 分類）
#
# 論文設定（Sec. IV-B2）：K=2 層 · hidden=128 · ReLU · dropout 0.2 ·
#   mean aggregator · full neighborhood sampling · CrossEntropy · Adam lr=1e-3
#   節點特徵初始化為全 1 向量（NIDS 資料集只有 flow/邊 特徵，節點 featureless）
#
# -----------------------------------------------------------------------------
# 本專案的兩項延伸（都做消融，不只照抄）：
#
# (1) 訓練/測試切分 —— 兩種都跑，因為它們回答不同問題：
#     random   : 照論文的 70/30 隨機切分。可與論文數字對比，但**同一次攻擊的邊
#                會同時落在訓練與測試**（同一秒、同一條連線的多筆邊高度相關），
#                因此是**樂觀偏誤**的估計。
#     scenario : 場景隔離 —— 用部分攻擊場景訓練、其餘場景測試。
#                回答「能不能泛化到沒見過的攻擊型態」，與本專案既有方法學一致。
#     ⚠️ 兩者若差距很大，代表 random 的高分主要來自資料洩漏而非泛化能力。
#
# (2) 節點特徵消融 —— 論文設為全 1 向量是因為它的資料集沒有節點特徵；
#     本專案的圖有節點特徵（含應用層 log），所以實測三種：
#       ones    : 全 1（照論文）
#       net     : 網路層節點特徵
#       net+log : 再加 log_lines_named / log_lines_null
#     這也順便檢驗上一輪 graph-level baseline 發現的「pooling 稀釋」問題：
#     edge-level 不做全圖 pooling，log 訊號是否就不會被稀釋掉？
#
# 執行： ml/venv/bin/python net/egraphsage.py <capture_dir>
# 輸出： <capture_dir>/graph/egraphsage_results.txt + .json
# =============================================================================
import os, sys, json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import MessagePassing
from sklearn.metrics import (precision_recall_fscore_support,
                             average_precision_score, roc_auc_score,
                             confusion_matrix)

EDGE_FEATS = ["n_pkts", "n_c2s", "n_s2c", "bytes_c2s",
              "bytes_s2c", "n_syn", "n_finrst", "max_payload"]
NET_NODE_FEATS = ["n_pkts", "bytes_c2s", "bytes_s2c", "n_syn",
                  "n_finrst", "max_payload", "degree"]
LOG_NODE_FEATS = ["log_lines_named", "log_lines_null"]
# 時序節點特徵（build_graph.py 項目3 產生）。放進 net 模式一起用。
TEMPORAL_FEATS = ["d_n_pkts", "roll_mean", "roll_std"]

# 論文 Sec. IV-B2 的設定
K_LAYERS, HIDDEN, DROPOUT, LR, EPOCHS = 2, 128, 0.2, 1e-3, 100
SEEDS = [42, 43, 44, 45, 46]

log = []
def out(s=""):
    print(s); log.append(str(s))


# =============================================================================
# E-GraphSAGE 層：Eq.4（聚合鄰域「邊」特徵）+ Eq.2（節點更新）
# =============================================================================
class EGraphSAGEConv(MessagePassing):
    """h^k_N(v) = mean({e_uv : u∈N(v)});  h^k_v = σ(W·[h^{k-1}_v ‖ h^k_N(v)])

    與 PyG 內建 SAGEConv 的差別：訊息不是鄰居的節點嵌入，而是**連到鄰居的那條邊
    的特徵**。這正是論文 Eq.4 的核心，也是「E-」(Edge) 的由來。
    """
    def __init__(self, in_node_dim, edge_dim, out_dim):
        super().__init__(aggr="mean")            # 論文用 mean aggregator
        self.lin = nn.Linear(in_node_dim + edge_dim, out_dim)

    def forward(self, x, edge_index, edge_attr):
        # propagate 會呼叫 message() 蒐集鄰域邊特徵，再依 aggr 聚合
        agg = self.propagate(edge_index, x=x, edge_attr=edge_attr)
        return self.lin(torch.cat([x, agg], dim=1))      # Eq.2 的 CONCAT

    def message(self, edge_attr):
        return edge_attr                          # Eq.4：訊息就是邊特徵本身


class EGraphSAGE(nn.Module):
    """K 層 E-GraphSAGE + Eq.5 邊嵌入 + 邊分類頭。"""
    def __init__(self, node_dim, edge_dim, hid=HIDDEN, k=K_LAYERS, n_cls=2):
        super().__init__()
        self.convs = nn.ModuleList()
        d = node_dim
        for _ in range(k):
            self.convs.append(EGraphSAGEConv(d, edge_dim, hid))
            d = hid
        self.drop = nn.Dropout(DROPOUT)
        # Eq.5：邊嵌入 = CONCAT(z_u, z_v) → 維度 2*hid
        self.cls = nn.Linear(hid * 2, n_cls)

    def forward(self, x, edge_index, edge_attr):
        h = x
        for i, conv in enumerate(self.convs):
            h = conv(h, edge_index, edge_attr)
            h = F.relu(h)
            if i < len(self.convs) - 1:
                h = self.drop(h)
        src, dst = edge_index
        z_uv = torch.cat([h[src], h[dst]], dim=1)        # Eq.5
        return self.cls(z_uv)


# =============================================================================
# 資料：把每秒一張圖「攤平」成一張大圖（各秒之間無連結）
# =============================================================================
def build_tensors(gdir, node_mode):
    """回傳一張 disjoint union 大圖 + 每條邊的 (label, scenario, sec)。

    每秒的圖彼此不連通，所以合成一張大圖不會讓訊息跨秒傳遞，
    但可以一次前向傳播算完所有邊 —— 比逐圖迴圈快很多。
    """
    nodes = pd.read_csv(os.path.join(gdir, "nodes.csv"))
    edges = pd.read_csv(os.path.join(gdir, "edges.csv"))

    # 全域節點索引：(scenario, sec, node) → id
    nodes = nodes.sort_values(["scenario", "sec", "node"]).reset_index(drop=True)
    nodes["gid"] = np.arange(len(nodes))
    key2gid = {(s, t, n): g for s, t, n, g in
               zip(nodes.scenario, nodes.sec, nodes.node, nodes.gid)}

    src = np.array([key2gid[(s, t, n)] for s, t, n in
                    zip(edges.scenario, edges.sec, edges.src)])
    dst = np.array([key2gid[(s, t, n)] for s, t, n in
                    zip(edges.scenario, edges.sec, edges.dst)])

    # 無向：兩個方向都建，讓兩端節點都能聚合到這條邊
    edge_index = torch.tensor(np.vstack([np.concatenate([src, dst]),
                                         np.concatenate([dst, src])]),
                              dtype=torch.long)
    ea = edges[EDGE_FEATS].values.astype(np.float32)
    edge_attr = torch.tensor(np.vstack([ea, ea]), dtype=torch.float)

    # 節點特徵（論文為全 1；本專案另做兩種消融）。時序特徵併入非 ones 模式，
    # 若舊資料沒有這些欄位則自動略過（向後相容）。
    have_temporal = all(c in nodes.columns for c in TEMPORAL_FEATS)
    if node_mode == "ones":
        x = torch.ones((len(nodes), len(EDGE_FEATS)), dtype=torch.float)
    else:
        cols = list(NET_NODE_FEATS)
        if have_temporal:
            cols += TEMPORAL_FEATS
        if node_mode == "net+log":
            cols += LOG_NODE_FEATS
        x = torch.tensor(nodes[cols].values.astype(np.float32), dtype=torch.float)

    y = torch.tensor(edges["is_attacker_edge"].values, dtype=torch.long)
    return dict(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y,
                n_edges=len(edges), scenario=edges.scenario.values,
                sec=edges.sec.values, node_mode=node_mode)


def normalize(d, train_mask):
    """標準化只 fit 在訓練邊上 —— 避免測試分布洩漏。"""
    n = d["n_edges"]
    ea = d["edge_attr"][:n]                      # 前半 = 原始方向
    mu, sd = ea[train_mask].mean(0), ea[train_mask].std(0)
    sd[sd == 0] = 1.0
    ea_n = (ea - mu) / sd
    d["edge_attr"] = torch.cat([ea_n, ea_n], dim=0)

    if d["node_mode"] != "ones":
        xm, xs = d["x"].mean(0), d["x"].std(0)
        xs[xs == 0] = 1.0
        d["x"] = (d["x"] - xm) / xs
    return d


# =============================================================================
# 訓練 / 評估
# =============================================================================
def run(d, train_mask, test_mask, seed):
    torch.manual_seed(seed); np.random.seed(seed)
    model = EGraphSAGE(d["x"].shape[1], d["edge_attr"].shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=LR)

    # 類別極不平衡（攻擊邊 0.3%）→ 用類別權重，否則模型會全預測正常
    n_pos = int(d["y"][train_mask].sum())
    n_neg = int(train_mask.sum()) - n_pos
    w = torch.tensor([1.0, max(n_neg / max(n_pos, 1), 1.0)], dtype=torch.float)
    lossf = nn.CrossEntropyLoss(weight=w)

    n = d["n_edges"]
    model.train()
    for _ in range(EPOCHS):
        opt.zero_grad()
        logits = model(d["x"], d["edge_index"], d["edge_attr"])[:n]
        loss = lossf(logits[train_mask], d["y"][train_mask])
        loss.backward(); opt.step()

    model.eval()
    with torch.no_grad():
        logits = model(d["x"], d["edge_index"], d["edge_attr"])[:n]
        prob = torch.softmax(logits, dim=1)[:, 1].numpy()
    return prob[test_mask.numpy()], d["y"][test_mask].numpy()


def metrics(prob, y):
    pred = (prob >= 0.5).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                 zero_division=0)
    nm = y == 0
    m = dict(precision=float(p), recall=float(r), f1=float(f),
             far=float(pred[nm].sum() / max(nm.sum(), 1)))
    if len(set(y)) > 1:
        m["pr_auc"] = float(average_precision_score(y, prob))
        m["roc_auc"] = float(roc_auc_score(y, prob))
    else:
        m["pr_auc"] = m["roc_auc"] = float("nan")
    return m


def evaluate(d, train_mask, test_mask, title, note):
    out("\n" + "-" * 78)
    out(title)
    out(note)
    ntr, nte = int(train_mask.sum()), int(test_mask.sum())
    out(f"  訓練邊 {ntr}（攻擊 {int(d['y'][train_mask].sum())}） · "
        f"測試邊 {nte}（攻擊 {int(d['y'][test_mask].sum())}）")

    runs = []
    for sd in SEEDS:
        prob, y = run(d, train_mask, test_mask, sd)
        m = metrics(prob, y)
        runs.append(m)
        out(f"    seed={sd}  P={m['precision']:.3f} R={m['recall']:.3f} "
            f"F1={m['f1']:.3f} FAR={m['far']:.2%} PR-AUC={m['pr_auc']:.3f}")

    agg = {}
    for k in ["precision", "recall", "f1", "far", "pr_auc", "roc_auc"]:
        v = np.array([r[k] for r in runs], dtype=float)
        v = v[~np.isnan(v)]
        agg[k] = dict(mean=float(v.mean()) if len(v) else float("nan"),
                      std=float(v.std()) if len(v) else float("nan"))
    out(f"  ➤ F1 = {agg['f1']['mean']:.3f} ± {agg['f1']['std']:.3f}   "
        f"PR-AUC = {agg['pr_auc']['mean']:.3f} ± {agg['pr_auc']['std']:.3f}   "
        f"FAR = {agg['far']['mean']:.2%}")
    return agg


def make_splits(d):
    """兩種切分。回傳 {名稱: (train_mask, test_mask, 說明)}。"""
    n = d["n_edges"]
    scen = d["scenario"]
    y = d["y"].numpy()
    splits = {}

    # (1) 論文的 70/30 隨機切分
    rng = np.random.RandomState(0)
    perm = rng.permutation(n)
    cut = int(n * 0.7)
    tr = torch.zeros(n, dtype=torch.bool); tr[perm[:cut]] = True
    te = torch.zeros(n, dtype=torch.bool); te[perm[cut:]] = True
    splits["random_70_30"] = (tr, te,
        "  照論文 Sec.VI-A：70% 訓練 / 30% 測試，隨機切分。\n"
        "  ⚠️ 同一次攻擊的多條邊會分散到兩邊 → 樂觀偏誤。")

    # (2) 場景隔離：用 S/T 的攻擊場景 + benign 訓練，R/RP/all 測試
    #     這樣測試集含**訓練時沒見過的攻擊型態**（R 否認、RP 重放）
    # (2) 場景隔離：用簡單攻擊訓練，**進階攻擊（stealth/compromised）測試**。
    #     這才是關鍵測試：模型能不能抓到「沒有流量指紋、身分合法」的攻擊 ——
    #     那正是規則與 RandomForest 都失效的地方。
    present = set(scen)
    adv = {"stealth", "compromised"} & present
    if adv:
        tr_scen = {s for s in present if s not in adv}
        tr = torch.tensor(np.isin(scen, list(tr_scen)))
        te = torch.tensor(np.isin(scen, list(adv)))
        splits["advanced_holdout"] = (tr, te,
            f"  進階攻擊隔離：{sorted(tr_scen)} 訓練 → {sorted(adv)} 測試。\n"
            "  ⭐ 測試集是**無流量指紋、身分合法**的攻擊，規則/RF 在此失效，\n"
            "     若 GNN 抓得到就證明了圖結構的價值。")
    else:
        tr_scen = {"benign", "S", "T"}
        tr = torch.tensor(np.isin(scen, list(tr_scen)))
        te = torch.tensor(~np.isin(scen, list(tr_scen)))
        splits["scenario_holdout"] = (tr, te,
            "  場景隔離：benign+S+T 訓練 → R/RP/all 測試（未見過的攻擊型態）。")
    return splits


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: egraphsage.py <capture_dir>")
    root = os.path.abspath(sys.argv[1])
    gdir = os.path.join(root, "graph")
    if not os.path.exists(os.path.join(gdir, "edges.csv")):
        sys.exit(f"找不到 {gdir}/edges.csv —— 請先跑 build_graph.py")

    out("=" * 78)
    out("E-GraphSAGE 邊分類 NIDS（Lo et al., NOMS 2022）")
    out("=" * 78)
    out(f"資料：{root}")
    out(f"論文設定：K={K_LAYERS} 層 · hidden={HIDDEN} · dropout={DROPOUT} · "
        f"mean aggregator · Adam lr={LR} · epochs={EPOCHS}")
    out(f"seeds={SEEDS}（論文只跑一次；本專案一律多 seed 報 mean±std）")
    out("")
    out("核心實作（忠於論文）：")
    out("  Eq.4  h^k_N(v) = mean({ e_uv : u∈N(v) })   ← 聚合鄰域『邊』特徵")
    out("  Eq.2  h^k_v    = σ(W·[h^{k-1}_v ‖ h^k_N(v)])")
    out("  Eq.5  z_uv     = CONCAT(z_u, z_v)          ← 邊嵌入 → 邊分類")

    results = {}
    for node_mode in ["ones", "net", "net+log"]:
        d = build_tensors(gdir, node_mode)
        splits = make_splits(d)
        label = {"ones": "全 1 向量（照論文，featureless）",
                 "net": "網路層節點特徵",
                 "net+log": "網路層 + 應用層 log 特徵"}[node_mode]
        out("\n" + "=" * 78)
        out(f"節點特徵：{label}（{d['x'].shape[1]} 維）")
        out("=" * 78)
        out(f"總邊數 {d['n_edges']}   攻擊邊 {int(d['y'].sum())} "
            f"({float(d['y'].float().mean()):.3%})")

        results[node_mode] = {}
        for sname, (tr, te, note) in splits.items():
            dd = normalize(build_tensors(gdir, node_mode), tr)
            results[node_mode][sname] = evaluate(dd, tr, te, f"切分：{sname}", note)

    # -----------------------------------------------------------------------
    out("\n" + "=" * 78)
    out("總覽：F1（mean ± std）")
    out("=" * 78)
    out(f"  {'節點特徵':<10}{'切分':<20}{'F1':>16}{'PR-AUC':>16}{'recall':>9}{'FAR':>9}")
    for nm in results:
        for sp in results[nm]:
            r = results[nm][sp]
            out(f"  {nm:<10}{sp:<20}"
                f"{r['f1']['mean']:>9.3f}±{r['f1']['std']:<6.3f}"
                f"{r['pr_auc']['mean']:>9.3f}±{r['pr_auc']['std']:<6.3f}"
                f"{r['recall']['mean']:>9.3f}{r['far']['mean']:>9.2%}")

    out("\n" + "=" * 78)
    out("解讀要點")
    out("=" * 78)
    out("- ⚠️ **兩種切分的 F1 不可直接比大小**：兩個測試集的攻擊比例不同")
    out("  （random 全場景混合 ≈0.30%；scenario 的 R/RP/all ≈0.53%，高 1.75 倍）。")
    out("  F1 會隨異常比例上升而變高（本專案已用重採樣實驗量化，見")
    out("  ml/EXPERIMENTS_V2.md 的比例實驗）。要跨切分比較請看 **PR-AUC / FAR /")
    out("  recall**，它們對比例不敏感。")
    out("- **節點特徵消融**：若 ones 與 net+log 差不多，代表本任務的資訊")
    out("  幾乎全在邊特徵裡 —— 這正是論文把節點設為 featureless 的理由。")
    out("- std 若接近 mean → 結果由隨機初始化主導，不可宣稱有效。")

    with open(os.path.join(gdir, "egraphsage_results.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in log) + "\n")
    with open(os.path.join(gdir, "egraphsage_summary.json"), "w", encoding="utf-8") as f:
        json.dump(dict(results=results, seeds=SEEDS, k=K_LAYERS, hidden=HIDDEN,
                       dropout=DROPOUT, lr=LR, epochs=EPOCHS),
                  f, ensure_ascii=False, indent=2)
    print(f"\n報告已存: {gdir}/egraphsage_results.txt")


if __name__ == "__main__":
    main()
