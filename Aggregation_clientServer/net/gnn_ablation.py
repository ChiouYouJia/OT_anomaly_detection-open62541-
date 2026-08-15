#!/usr/bin/env python3
# =============================================================================
# gnn_ablation.py ── 第三輪 TODO 的 3-1 / 3-2 / 3-3 三個消融，一次跑完
# =============================================================================
# 背景（見 TODO_next_experiments.md 第三輪）：
#   第二輪的結論「無標籤下只有 GNN 抓得到 compromised」有兩個沒被檢驗的前提，
#   而第三輪的規則堆疊實驗（router_fusion.py 第二段）已經動搖了它 ——
#   一條零訓練規則 D5（report_dev_own > 0.1）在 compromised 與 compromised_group
#   上都是 recall 100% / benign 零誤報，而 GNN(D3) 在告警路徑上毫無貢獻。
#   所以必須先把「GNN 的分數到底從哪來」查清楚，才談得上後續的主張。
#
# ── 三個消融 ────────────────────────────────────────────────────────────────
#   3-1 值特徵消融：VAL_FEATS 拿掉 report_dev
#       report_dev = 該節點回報值「對全域真值的偏差」——**那就是答案本身**。
#       GNN_DATASET.md 已自承舊 compromised 的 C=0.226 有一部分是這樣來的：
#       「攻擊者的 report_dev 本身就 17.77，GNN 不必真做 peer 比對就看得到」。
#       只留 report_val（該節點回報了什麼）才逼模型真的去跟 peer 比。
#
#   3-2 結構消融：拿掉訊息傳遞
#       現有 A/B/C 三組裡，C 同時改變了兩件事 —— per-node 值表示法**和**圖結構，
#       所以「C ≫ B」無法區分贏在哪一個。本消融把 edge_index 換成只有自環、
#       peer 上下文強制為 0，其餘（容量、超參、訓練流程）完全不動
#       → 等價於同容量的 MLP + pooling。**這一組沒做，任何審查者都會問。**
#
#   3-3 評分粒度：graph-level max pooling vs node-level
#       現況 score = 圖內回報節點的**最大**重建誤差 → 一個吵的節點就拉高整張圖。
#       router_fusion 的診斷顯示背景率高達 17.6%(compromised) ~ 97.3%(stealth)，
#       很可能就是這個 max 造成的。node-level 直接對節點評分，另外還能回答
#       「哪一台被冒用」——這是 graph-level 給不出來的運維資訊。
#
# ── node-level ground truth 的來源（誠實標注）────────────────────────────────
#   nodes.csv 的 label 只標了「匿名寫入者」那個節點（S/R/T/all/stealth 的
#   log_writer），**compromised / compromised_group 沒有節點標籤** —— 因為攻擊者
#   冒用合法 motor 身分，圖上不存在額外節點。
#   本腳本用採集設計本身來定 ground truth：攻擊者綁定專屬來源 IP，因此它在整個
#   場景中固定是同一個節點名。實測兩個場景都是 `motor_7`（20 秒，與 20 個注入秒
#   完全對應）。這個身分來自**採集時的 IP 綁定**，不是從偵測特徵反推的。
#
# 執行： ml/venv/bin/python net/gnn_ablation.py <capture_dir>
# 輸出： <capture_dir>/graph/gnn_ablation_results.txt + .json
# =============================================================================
import os, sys, json
import numpy as np
import torch
from sklearn.metrics import average_precision_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import graph_clf as gc

SEEDS = [42, 43, 44, 45, 46]
BUDGET = 0.999          # 門檻 = benign 訓練分數的 99.9 分位（與 router_fusion 一致）
ATTACKER_NODE = "motor_7"   # 見檔頭「node-level ground truth」
VAL_SCEN = ["compromised", "compromised_group"]

log = []
def out(s=""):
    print(s); log.append(str(s))


# =============================================================================
# 一次訓練 = 一個 (值特徵集合, 是否用圖結構, seed)
# =============================================================================
def train_ae(d, tr, seed, val_feats, use_graph, drop_dev=True):
    """回傳 (每節點重建誤差, 每圖分數)。除了消融旋鈕，其餘與 graph_clf 完全相同。

    ⚠️ drop_dev（2026-08-10 修）：`CTX_FEATS` 的定義是「NODE_FEATS_C 扣掉
    VAL_FEATS」，所以把 report_dev 移出 val_feats **並不會讓它消失** —— 它會被
    推到 context 那一側，模型照樣看得到。本檔初版的 V1/V3 就是這樣，宣稱「已經
    拿掉答案」並不成立。drop_dev=True 才是真的從兩側都拿掉。
    """
    nodes = d["nodes"]
    ctx_feats = [c for c in gc.NODE_FEATS_C if c not in val_feats]
    if drop_dev and "report_dev" not in val_feats:
        ctx_feats = [c for c in ctx_feats if c != "report_dev"]
    x_ctx = torch.tensor(nodes[ctx_feats].values.astype(np.float32))
    x_val = torch.tensor(nodes[val_feats].values.astype(np.float32))
    peer_mask = torch.tensor((nodes["report_val"].values != 0).astype(np.float32))
    gid = d["graph_id"]
    n_nodes = x_ctx.shape[0]

    nmask = torch.tensor(gc._node_mask(d, tr))
    for X in (x_ctx, x_val):
        mu, sd_ = X[nmask].mean(0), X[nmask].std(0)
        sd_[sd_ == 0] = 1.0
        X.sub_(mu).div_(sd_)

    if use_graph:
        ei, ea = d["edge_index"], d["edge_attr"]
        n_ed = ea.shape[0] // 2
        tr_e = gc._edge_mask(d, tr)
        mu, sd_ = ea[:n_ed][tr_e].mean(0), ea[:n_ed][tr_e].std(0)
        sd_[sd_ == 0] = 1.0
        ea_n = (ea - mu) / sd_
        hop2 = gc.make_hop2_peer(ei, n_nodes, peer_mask)
    else:
        # 無訊息傳遞：邊只剩自環（conv 只看得到自己）、peer 上下文恆為 0。
        # 容量與超參完全不變 → 這就是同容量的 MLP + pooling 對照組。
        idx = torch.arange(n_nodes, dtype=torch.long)
        ei = torch.vstack([idx, idx])
        ea_n = torch.zeros(n_nodes, d["edge_attr"].shape[1])
        hop2 = lambda v: torch.zeros_like(v)

    torch.manual_seed(seed); np.random.seed(seed)
    model = gc.GraphValueAE(x_ctx.shape[1], x_val.shape[1], d["edge_attr"].shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=gc.AE_LR)
    w = peer_mask.unsqueeze(1)
    model.train()
    for _ in range(gc.AE_EPOCHS):
        opt.zero_grad()
        pred = model(x_ctx, x_val, ei, ea_n, gid, d["n_graphs"], peer_mask, hop2)
        err = ((pred - x_val) ** 2) * w
        (err[nmask].sum() / w[nmask].sum().clamp(min=1.0)).backward()
        opt.step()
    model.eval()
    with torch.no_grad():
        pred = model(x_ctx, x_val, ei, ea_n, gid, d["n_graphs"], peer_mask, hop2)
        node_err = (((pred - x_val) ** 2).mean(1) * peer_mask).numpy()
        gscore = gc.scatter(torch.tensor(node_err), gid, dim=0,
                            dim_size=d["n_graphs"], reduce="max").numpy()
    return node_err, gscore


# =============================================================================
# 評估
# =============================================================================
def graph_eval(d, gscore, tr, te, y, scen):
    """圖級：逐場景 PR-AUC + 非注入秒的背景命中率（門檻取 benign 訓練分位）。"""
    thr = float(np.quantile(gscore[tr], BUDGET)) if tr.sum() else 0.0
    hit = gscore > thr
    r = {}
    for s in sorted(set(scen[te])):
        m = te & (scen == s)
        mal, ben = m & (y == 1), m & (y == 0)
        r[s] = dict(
            pr_auc=float(average_precision_score(y[m], gscore[m]))
            if mal.sum() and ben.sum() else float("nan"),
            recall=float(hit[mal].mean()) if mal.sum() else float("nan"),
            bg_rate=float(hit[ben].mean()) if ben.sum() else float("nan"))
    return r


def node_eval(d, node_err, te):
    """節點級：能不能指認出被冒用的那一台。

    只在 compromised / compromised_group 的**注入秒**上評估，候選集合 = 該秒所有
    有回報值的節點（motor + sensor server）。兩個指標：
      · top1  ：重建誤差最高的節點是否就是攻擊者 → 「指認」能力
      · PR-AUC：把該場景所有回報節點排序的品質（含非注入秒，故偏保守）
    """
    nodes = d["nodes"]
    gid = d["graph_id"].numpy()
    te_node = np.array([te[g] for g in gid])
    has_val = nodes["report_val"].values != 0
    r = {}
    for s in VAL_SCEN:
        m = te_node & (nodes["scenario"].values == s) & has_val
        if not m.sum():
            continue
        is_atk = (nodes["node"].values == ATTACKER_NODE)
        # 注入秒 = 該節點所在的圖 label=1
        glab = d["y"].numpy()
        inj = np.array([glab[g] == 1 for g in gid])
        ylab = (m & is_atk & inj).astype(int)
        top1, n_sec = 0, 0
        for sec in np.unique(nodes["sec"].values[m & inj]):
            sel = m & inj & (nodes["sec"].values == sec)
            if not sel.sum():
                continue
            n_sec += 1
            idx = np.where(sel)[0]
            if nodes["node"].values[idx[np.argmax(node_err[idx])]] == ATTACKER_NODE:
                top1 += 1
        r[s] = dict(top1=float(top1 / n_sec) if n_sec else float("nan"),
                    n_inj_sec=int(n_sec),
                    pr_auc=float(average_precision_score(ylab[m], node_err[m]))
                    if ylab[m].sum() and (ylab[m] == 0).any() else float("nan"))
    return r


def agg(runs, path):
    """runs = [dict...]；path = ('scen','key') 取值後回傳 mean±std 字串。"""
    v = [r[path[0]][path[1]] for r in runs if path[0] in r]
    v = [x for x in v if not np.isnan(x)]
    if not v:
        return "   —   "
    return f"{np.mean(v):.3f}±{np.std(v):.3f}"


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: gnn_ablation.py <capture_dir>")
    root = os.path.abspath(sys.argv[1])
    gdir = os.path.join(root, "graph")
    d = gc.load(gdir)
    tr, te = gc.one_class_split(d)
    y, scen = d["y"].numpy(), d["scen"]

    out("=" * 78)
    out("GNN 消融：3-1 值特徵 / 3-2 訊息傳遞 / 3-3 評分粒度")
    out("=" * 78)
    out(f"資料 {root}")
    out(f"總圖數 {d['n_graphs']}  攻擊圖 {int(y.sum())}  "
        f"benign 訓練 {int(tr.sum())} · 測試 {int(te.sum())}")
    out(f"門檻 = benign 訓練分數 {BUDGET:.1%} 分位；{len(SEEDS)} seeds 報 mean±std")
    out(f"節點級 ground truth：攻擊者節點 = {ATTACKER_NODE}（採集時綁定專屬來源 IP）")

    # ⚠️ V1/V3 的語意已於 2026-08-10 修正：初版只把 report_dev 移出 val_feats，
    #    它其實跑到 ctx 去了（見 train_ae 的 drop_dev 說明）。初版跑出的
    #    V1=0.051 / V3=0.053 是在「模型仍看得到 report_dev」的條件下量的。
    variants = [
        ("V0 現況（值含 report_dev · 有圖）", ["report_val", "report_dev"], True),
        ("V1 report_dev 兩側都拿掉 · 有圖", ["report_val"], True),
        ("V2 值含 report_dev · 無圖", ["report_val", "report_dev"], False),
        ("V3 兩者都拿掉（最誠實對照）", ["report_val"], False),
    ]

    res = {}
    for name, vf, ug in variants:
        gruns, nruns = [], []
        for sd in SEEDS:
            ne, gs = train_ae(d, tr, sd, vf, ug)
            gruns.append(graph_eval(d, gs, tr, te, y, scen))
            nruns.append(node_eval(d, ne, te))
        res[name] = dict(graph=gruns, node=nruns,
                         val_feats=vf, use_graph=ug)
        out(f"  [{name}] 完成")

    scen_order = [s for s in ["compromised", "compromised_group", "stealth",
                              "S", "T", "R", "RP", "all", "benign"]
                  if s in set(scen[te])]

    # ── 圖級 PR-AUC ──────────────────────────────────────────────────────
    out("\n" + "=" * 78)
    out("圖級 one-class PR-AUC（越高越好；對照：D5 規則在兩個 compromised 上 R=1.0/FP=0）")
    out("=" * 78)
    out(f"  {'變體':<34}" + "".join(f"{s[:11]:>13}" for s in scen_order))
    for name in res:
        out(f"  {name:<34}" +
            "".join(f"{agg(res[name]['graph'], (s, 'pr_auc')):>13}"
                    for s in scen_order))

    # ── 背景率（3-3 的核心診斷）──────────────────────────────────────────
    out("\n" + "=" * 78)
    out("非注入秒的背景命中率（越低越好 —— 高背景率代表『偵測到』是噪音撞出來的）")
    out("=" * 78)
    out(f"  {'變體':<34}" + "".join(f"{s[:11]:>13}" for s in scen_order))
    for name in res:
        out(f"  {name:<34}" +
            "".join(f"{agg(res[name]['graph'], (s, 'bg_rate')):>13}"
                    for s in scen_order))

    # ── 節點級（3-3 的產出）─────────────────────────────────────────────
    out("\n" + "=" * 78)
    out(f"節點級：注入秒裡重建誤差最高的節點是否就是攻擊者（top1）")
    out("=" * 78)
    out(f"  {'變體':<34}" +
        "".join(f"{s[:16]+' top1':>22}" for s in VAL_SCEN))
    for name in res:
        out(f"  {name:<34}" +
            "".join(f"{agg(res[name]['node'], (s, 'top1')):>22}" for s in VAL_SCEN))
    out("\n  （隨機猜的基準 = 1 / 該秒有回報值的節點數，實測每張圖約 9 個 → ≈0.11）")

    with open(os.path.join(gdir, "gnn_ablation_results.txt"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(log) + "\n")
    with open(os.path.join(gdir, "gnn_ablation_summary.json"), "w") as f:
        json.dump({k: dict(val_feats=v["val_feats"], use_graph=v["use_graph"],
                           graph=v["graph"], node=v["node"])
                   for k, v in res.items()}, f, indent=2, ensure_ascii=False)
    out(f"\n報告已存: {gdir}/gnn_ablation_results.txt")


if __name__ == "__main__":
    main()
