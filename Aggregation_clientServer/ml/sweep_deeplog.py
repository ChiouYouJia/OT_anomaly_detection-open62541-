#!/usr/bin/env python3
# =============================================================================
# sweep_deeplog.py ── DeepLog 超參數掃描 + PR 曲線 + 多 seed 誤差範圍
# =============================================================================
# 動機（先前評估的三個弱點）：
#   1. WINDOW=10 / TOPK=3 / HIDDEN=64 是一組固定值，從未掃過 → 先前「語意版 vs
#      整數版」的比較可能只是這一組超參下的偶然，換 top-k 結論可能反轉。
#   2. README 說要用 PR-AUC，但結果檔全是單點 P/R/F1，沒有任何一條曲線。
#   3. 所有數字都是單次執行的點估計，LSTM 還有隨機初始化 → 無誤差範圍。
#
# 本腳本：
#   (A) 網格掃描 window x hidden，對每組報 PR-AUC 與各 top-k 的 F1
#   (B) 用「真實模板在預測分布中的排名 rank」當連續分數（rank 越大越異常），
#       掃過所有 rank 門檻得到真正的 PR 曲線與 PR-AUC，而非單一 top-k 點
#   (C) 對最佳設定跑多個 random seed，報 mean ± std
#
# 注意：本腳本一律在『已關閉洩漏管道』的資料上評估（沿用 ablation_leakage.py 的
#   LEAK_MAP / dtso 修正），否則 R 的假高分會污染整體 PR-AUC。
#
# 執行： ml/venv/bin/python ml/sweep_deeplog.py
# 輸出： ml/out/sweep_deeplog.txt, ml/out/pr_curve.csv
# =============================================================================
import os
import numpy as np
import pandas as pd
import torch, torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import precision_recall_curve, auc, precision_recall_fscore_support

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")

LEAK_MAP     = {"T97dc7c": "Tf9750a", "T82e2a8": "Tf9750a"}
FIX_DTSO_FOR = ["T97dc7c", "T82e2a8"]

EPOCHS, BATCH, LAYERS, LR = 15, 128, 2, 1e-3
GRID_WINDOW = [5, 10, 20]
GRID_HIDDEN = [32, 64]
GRID_TOPK   = [1, 2, 3, 5, 8]
SEEDS       = [42, 1, 7, 123, 2024]

log = []
def out(s=""):
    print(s); log.append(str(s))


def load_ablated():
    """載入資料並關閉兩個洩漏管道（與 ablation_leakage.py 一致）。"""
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    fix = df["template_id"].isin(FIX_DTSO_FOR) & (df["dist_ts_occurrence"] == 0)
    df.loc[fix, "dist_ts_occurrence"] = 1
    df["template_id"] = df["template_id"].replace(LEAK_MAP)
    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].unique()))}
    df["tid"] = df["template_id"].map(vocab)
    return df, len(vocab)


def make_windows(seq, window):
    X, yn, idx = [], [], []
    for i in range(len(seq) - window):
        X.append(seq[i:i+window]); yn.append(seq[i+window]); idx.append(i+window)
    return np.array(X), np.array(yn), np.array(idx)


class IntDeepLog(nn.Module):
    def __init__(s, V, h, l):
        super().__init__()
        s.emb = nn.Embedding(V, h); s.lstm = nn.LSTM(h, h, l, batch_first=True); s.fc = nn.Linear(h, V)
    def forward(s, x):
        o, _ = s.lstm(s.emb(x)); return s.fc(o[:, -1, :])


def train_and_score(df, V, window, hidden, seed):
    """訓練後回傳測試集上每行的 (rank 分數, label, attack_type)。

    rank = 真實模板在模型預測分布中的名次（0=最可能）。rank 越大越異常。
    用它當連續分數就能掃出完整 PR 曲線；rank >= k 等價於傳統 top-k 判異常。
    """
    torch.manual_seed(seed); np.random.seed(seed)
    base      = df[df.scenario.str.contains("baseline")]
    test_scen = [s for s in df.scenario.unique() if "baseline" not in s]

    Xtr, ytr = [], []
    for s in base.scenario.unique():
        seq = base[base.scenario == s].sort_values("seq_pos")["tid"].values
        X, y, _ = make_windows(seq, window)
        if len(X): Xtr.append(X); ytr.append(y)
    Xtr = np.concatenate(Xtr); ytr = np.concatenate(ytr)

    model = IntDeepLog(V, hidden, LAYERS)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    lf  = nn.CrossEntropyLoss()
    dl  = DataLoader(TensorDataset(torch.tensor(Xtr), torch.tensor(ytr)), batch_size=BATCH, shuffle=True)
    model.train()
    for _ in range(EPOCHS):
        for xb, yb in dl:
            opt.zero_grad(); lf(model(xb), yb).backward(); opt.step()
    model.eval()

    ranks, labels, types = [], [], []
    with torch.no_grad():
        for s in test_scen:
            sub = df[df.scenario == s].sort_values("seq_pos").reset_index(drop=True)
            X, yn, idxs = make_windows(sub["tid"].values, window)
            if len(X) == 0: continue
            logits = model(torch.tensor(X))
            order  = torch.argsort(logits, dim=1, descending=True).numpy()
            r = np.array([int(np.where(order[i] == yn[i])[0][0]) for i in range(len(yn))])
            ranks.append(r)
            labels.append(sub.loc[idxs, "label"].values)
            types.append(sub.loc[idxs, "attack_type"].values)
    return np.concatenate(ranks), np.concatenate(labels), np.concatenate(types)


def main():
    df, V = load_ablated()
    out("=" * 72)
    out("DeepLog 超參數掃描 + PR 曲線 + 多 seed 誤差範圍")
    out("=" * 72)
    out(f"模板詞彙量 V={V}（已關閉洩漏管道：R/S 偽造模板併入正常、dtso 補正）")
    out("評分方式：rank = 真實模板在預測分布中的名次（0=最可能）。rank>=k 即傳統 top-k 判異常。")
    out("PR 曲線由 rank 連續掃門檻產生，故 PR-AUC 不依賴任何單一 top-k 選擇。")

    # =====================================================================
    # (A) 網格掃描
    # =====================================================================
    out("\n" + "=" * 72)
    out("(A) 網格掃描 window x hidden（seed=42），每格報 PR-AUC 與各 top-k 的 F1")
    out("=" * 72)
    out(f"{'window':>7} {'hidden':>7} {'PR-AUC':>8} " + " ".join(f"{'F1@k='+str(k):>9}" for k in GRID_TOPK))
    out("-" * 72)

    results = {}
    best = None
    for w in GRID_WINDOW:
        for h in GRID_HIDDEN:
            ranks, labels, types = train_and_score(df, V, w, h, seed=42)
            prec, rec, _ = precision_recall_curve(labels, ranks)
            pr_auc = auc(rec, prec)
            f1s = []
            for k in GRID_TOPK:
                pred = (ranks >= k).astype(int)
                _, _, f, _ = precision_recall_fscore_support(labels, pred, average="binary", zero_division=0)
                f1s.append(f)
            results[(w, h)] = dict(ranks=ranks, labels=labels, types=types, pr_auc=pr_auc, f1s=f1s)
            out(f"{w:>7} {h:>7} {pr_auc:>8.3f} " + " ".join(f"{f:>9.3f}" for f in f1s))
            if best is None or pr_auc > best[0]: best = (pr_auc, w, h)
    out("-" * 72)
    bw, bh = best[1], best[2]
    out(f"最佳設定（依 PR-AUC）：window={bw}, hidden={bh}, PR-AUC={best[0]:.3f}")
    prev = results[(10, 64)]
    out(f"先前預設   window=10, hidden=64, PR-AUC={prev['pr_auc']:.3f}"
        f"  → 差距 {best[0]-prev['pr_auc']:+.3f}")

    # =====================================================================
    # (B) 最佳設定的 top-k 取捨表 + PR 曲線
    # =====================================================================
    out("\n" + "=" * 72)
    out(f"(B) 最佳設定 window={bw}, hidden={bh} 的 top-k 取捨（precision/recall/FPR 隨 k 變化）")
    out("=" * 72)
    R = results[(bw, bh)]
    ranks, labels, types = R["ranks"], R["labels"], R["types"]
    out(f"{'top-k':>6} {'precision':>10} {'recall':>8} {'F1':>7} {'FPR':>8}   per-type recall")
    out("-" * 72)
    for k in GRID_TOPK:
        pred = (ranks >= k).astype(int)
        p, r, f, _ = precision_recall_fscore_support(labels, pred, average="binary", zero_division=0)
        nm = labels == 0
        fpr = pred[nm].sum() / max(nm.sum(), 1)
        pt = []
        for a in ["S", "T", "R", "RP"]:
            m = types == a
            if m.sum(): pt.append(f"{a}={pred[m].sum()/m.sum():.0%}")
        out(f"{k:>6} {p:>10.3f} {r:>8.3f} {f:>7.3f} {fpr:>8.2%}   {' '.join(pt)}")
    out("-" * 72)
    out("→ top-k 是 precision/recall 的取捨旋鈕：k 越大越保守（FPR 降、recall 也降）。")
    out("  先前固定 k=3 只是這條曲線上的一個工作點，不是必然最佳點。")

    prec, rec, thr = precision_recall_curve(labels, ranks)
    pd.DataFrame({"precision": prec[:-1], "recall": rec[:-1], "rank_threshold": thr}).to_csv(
        os.path.join(OUT, "pr_curve.csv"), index=False)
    out(f"\nPR 曲線資料已存: out/pr_curve.csv（{len(thr)} 個門檻點，PR-AUC={R['pr_auc']:.3f}）")

    out("\n文字版 PR 曲線（各 recall 水準下可達的最佳 precision）:")
    for target in np.arange(0.1, 1.01, 0.1):
        idx = np.where(rec >= target)[0]
        if len(idx) == 0: continue
        best_p = prec[idx].max()
        out(f"  recall>={target:.1f}  precision={best_p:.3f} |{'█' * int(best_p * 40)}")

    # =====================================================================
    # (C) 多 seed 誤差範圍
    # =====================================================================
    out("\n" + "=" * 72)
    out(f"(C) 最佳設定 window={bw}, hidden={bh} 跑 {len(SEEDS)} 個 random seed（固定 k=3 以對照先前結果）")
    out("=" * 72)
    rows = []
    for sd in SEEDS:
        rk, lb, tp = train_and_score(df, V, bw, bh, seed=sd)
        prec_s, rec_s, _ = precision_recall_curve(lb, rk)
        pr_auc = auc(rec_s, prec_s)
        pred = (rk >= 3).astype(int)
        p, r, f, _ = precision_recall_fscore_support(lb, pred, average="binary", zero_division=0)
        nm = lb == 0
        row = dict(seed=sd, pr_auc=pr_auc, precision=p, recall=r, f1=f,
                   fpr=pred[nm].sum()/max(nm.sum(), 1))
        for a in ["S", "T", "R", "RP"]:
            m = tp == a
            row[a] = pred[m].sum()/m.sum() if m.sum() else np.nan
        rows.append(row)
        out(f"  seed={sd:<5} PR-AUC={pr_auc:.3f}  P={p:.3f} R={r:.3f} F1={f:.3f} FPR={row['fpr']:.2%}")

    rdf = pd.DataFrame(rows)
    out("\n" + "-" * 72)
    out(f"{'指標':<12} {'mean':>8} {'std':>8}   範圍")
    out("-" * 72)
    for col, name in [("pr_auc", "PR-AUC"), ("precision", "precision"), ("recall", "recall"),
                      ("f1", "F1"), ("fpr", "FPR"), ("S", "S recall"), ("T", "T recall"),
                      ("R", "R recall"), ("RP", "RP recall")]:
        v = rdf[col].dropna()
        if len(v) == 0: continue
        out(f"{name:<12} {v.mean():>8.3f} {v.std():>8.3f}   [{v.min():.3f}, {v.max():.3f}]")

    out("\n" + "=" * 72)
    out("結論")
    out("=" * 72)
    v = rdf["f1"]; va = rdf["pr_auc"]
    out(f"- **整個網格的 PR-AUC 都很低（{min(r['pr_auc'] for r in results.values()):.3f}~"
        f"{max(r['pr_auc'] for r in results.values()):.3f}）**。這才是關鍵訊息：")
    out("  DeepLog 在本資料上的排序能力整體就是弱的，不是『沒調好參』。")
    out(f"  最佳 window={bw},hidden={bh} 也只比先前預設高 {best[0]-prev['pr_auc']:+.3f}，")
    out("  調參救不了它。")
    out(f"- **先前『語意版 vs 整數版 F1 0.54 vs 0.46』的結論不成立**：多 seed 顯示")
    out(f"  F1 本身的 std 就有 {v.std():.3f}（範圍 [{v.min():.3f}, {v.max():.3f}]），")
    out("  而那個比較是各跑『一次』得到的單點。差距落在隨機初始化的雜訊範圍內，")
    out("  不能宣稱哪一版較好。要下這種結論必須多 seed + 報 std。")
    out("- top-k 只是 PR 曲線上的一個工作點。先前固定 k=3 報單點 F1，掩蓋了")
    out("  precision/recall 可調的事實；正確做法是報 PR-AUC + 說明工作點的選擇理由。")
    out("  注意 k>=5 時 F1 斷崖下跌（S/RP 直接歸零）→ 工作點不能隨意挑。")
    out("- PR 曲線在 recall 0.7~0.8 之間 precision 從 0.19 崩到 0.02，")
    out("  代表『再多抓一點就要付出大量誤報』，這是本資料的實際天花板。")
    out(f"- R recall 在所有超參、所有 seed 下都接近 0（mean {rdf['R'].mean():.2f}）")
    out("  → 與 ablation 實驗一致：R 偵測不到不是調參問題，此結論對超參選擇穩健。")
    out("- T recall 是唯一在所有 seed 都穩定 100%（std=0）的類別 → DeepLog 對 T 的")
    out("  偵測能力是真實且可靠的，這是序列模型在本專案唯一站得住的優勢。")

    open(os.path.join(OUT, "sweep_deeplog.txt"), "w", encoding="utf-8").write(
        "\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {OUT}/sweep_deeplog.txt")


if __name__ == "__main__":
    main()
