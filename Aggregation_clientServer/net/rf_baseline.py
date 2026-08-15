#!/usr/bin/env python3
# =============================================================================
# rf_baseline.py ── 不用圖的邊分類基線（RandomForest）
# =============================================================================
# 為什麼要有這個：
#   GNN 的價值主張是「圖結構帶來額外資訊」。要證明這一點，必須有一個**不用圖**
#   的對照 —— 若 RandomForest（只看單條邊自己的特徵）就能做到一樣好，那圖結構
#   沒有加值。net/GNN_DATASET.md 先前正是用它揭穿了「舊資料的攻擊邊有指紋、
#   任務太簡單」的問題（RF PR-AUC=1.000）。
#
#   本腳本在**進階攻擊**（stealth / compromised）上重跑同樣的對照：
#   若 RF 在進階攻擊上掉下來、而 GNN 撐得住，就證明了圖結構的價值。
#
# 用與 egraphsage.py 完全相同的切分與特徵，確保可直接對比。
#
# 執行： ml/venv/bin/python net/rf_baseline.py <capture_dir>
# =============================================================================
import os, sys, json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (precision_recall_fscore_support,
                             average_precision_score, roc_auc_score)

EDGE_FEATS = ["n_pkts", "n_c2s", "n_s2c", "bytes_c2s",
              "bytes_s2c", "n_syn", "n_finrst", "max_payload"]
SEEDS = [42, 43, 44, 45, 46]

log = []
def out(s=""):
    print(s); log.append(str(s))


def metrics(prob, y):
    pred = (prob >= 0.5).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                 zero_division=0)
    nm = y == 0
    m = dict(precision=float(p), recall=float(r), f1=float(f),
             far=float(pred[nm].sum() / max(nm.sum(), 1)))
    m["pr_auc"] = float(average_precision_score(y, prob)) if len(set(y)) > 1 else float("nan")
    m["roc_auc"] = float(roc_auc_score(y, prob)) if len(set(y)) > 1 else float("nan")
    return m


def evaluate(X, y, tr, te, title, note):
    out("\n" + "-" * 78)
    out(title); out(note)
    out(f"  訓練 {int(tr.sum())} 邊（攻擊 {int(y[tr].sum())}） · "
        f"測試 {int(te.sum())} 邊（攻擊 {int(y[te].sum())}）")
    if y[tr].sum() == 0:
        out("  ⚠ 訓練集無攻擊樣本，跳過"); return None
    runs = []
    for sd in SEEDS:
        rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                    random_state=sd, n_jobs=-1)
        rf.fit(X[tr], y[tr])
        prob = rf.predict_proba(X[te])[:, 1]
        runs.append(metrics(prob, y[te]))
    agg = {}
    for k in ["precision", "recall", "f1", "far", "pr_auc", "roc_auc"]:
        v = np.array([r[k] for r in runs], dtype=float); v = v[~np.isnan(v)]
        agg[k] = dict(mean=float(v.mean()) if len(v) else float("nan"),
                      std=float(v.std()) if len(v) else float("nan"))
    out(f"  ➤ F1 = {agg['f1']['mean']:.3f} ± {agg['f1']['std']:.3f}   "
        f"PR-AUC = {agg['pr_auc']['mean']:.3f} ± {agg['pr_auc']['std']:.3f}   "
        f"recall = {agg['recall']['mean']:.3f}   FAR = {agg['far']['mean']:.2%}")
    return agg


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: rf_baseline.py <capture_dir>")
    gdir = os.path.join(os.path.abspath(sys.argv[1]), "graph")
    edges = pd.read_csv(os.path.join(gdir, "edges.csv"))
    X = edges[EDGE_FEATS].values.astype(np.float32)
    y = edges["is_attacker_edge"].values.astype(int)
    scen = edges["scenario"].values

    out("=" * 78)
    out("RandomForest 邊分類基線（不用圖）")
    out("=" * 78)
    out(f"資料：{gdir}")
    out(f"總邊 {len(y)}  攻擊邊 {int(y.sum())} ({y.mean():.4%})  特徵 {len(EDGE_FEATS)} 維")
    out("目的：作為 GNN 的對照 —— RF 若也很高，代表圖結構沒有加值。")

    results = {}

    # 切分與 egraphsage.py 一致
    n = len(y)
    rng = np.random.RandomState(0); perm = rng.permutation(n); cut = int(n * 0.7)
    tr = np.zeros(n, bool); tr[perm[:cut]] = True
    te = ~tr
    results["random_70_30"] = evaluate(X, y, tr, te,
        "切分：random_70_30", "  70/30 隨機切分（樂觀偏誤）。")

    present = set(scen); adv = {"stealth", "compromised"} & present
    if adv:
        tr = ~np.isin(scen, list(adv)); te = np.isin(scen, list(adv))
        results["advanced_holdout"] = evaluate(X, y, tr, te,
            "切分：advanced_holdout",
            f"  {sorted(present-adv)} 訓練 → {sorted(adv)} 測試。\n"
            "  ⭐ 關鍵：進階攻擊沒有流量指紋，RF 應該在此掉下來。")

    out("\n" + "=" * 78)
    out("解讀")
    out("=" * 78)
    out("- 若 RF 在 advanced_holdout 上 PR-AUC 很低、而 GNN（egraphsage.py）較高，")
    out("  → **證明圖結構帶來了不用圖的方法拿不到的資訊**，這是本輪實驗的目標。")
    out("- 若兩者都低 → 進階攻擊在目前特徵下都難偵測，需要更強的跨節點特徵。")
    out("- 若 RF 仍然很高 → 進階攻擊還是留下了單邊指紋，攻擊設計要再收斂。")

    open(os.path.join(gdir, "rf_results.txt"), "w", encoding="utf-8").write(
        "\n".join(str(x) for x in log) + "\n")
    with open(os.path.join(gdir, "rf_summary.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n報告已存: {gdir}/rf_results.txt")


if __name__ == "__main__":
    main()
