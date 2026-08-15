#!/usr/bin/env python3
# =============================================================================
# compare_ngram_deeplog.py ── n-gram vs DeepLog(LSTM) 的公平對照
# =============================================================================
# 為什麼需要這支腳本（deeplog.py 的數字不能直接拿來比）：
#   1. 切分不同：deeplog.py 用 scenario.startswith("baseline") 選訓練集，
#      而 `v2_baseline_60min_...` 是 "v2_" 開頭 → 它被丟進了測試集。
#      結果 DeepLog 少了 7264 行訓練資料，測試集卻多了 7264 行純正常
#      （TN 被灌水、FPR 被稀釋）。ngram_detector.py 兩個 baseline 都當訓練。
#   2. 評估位置不同：DeepLog 每個場景跳過前 WINDOW 行（沒有足夠上下文），
#      n-gram 用 padding 從第 1 行就評分 → 分母不一樣。
#   3. 指標不同：DeepLog 只有 top-k 二元判定，沒有連續分數，無法算 PR-AUC。
#
# 本腳本的對齊做法：
#   * 兩個模型共用 ngram_detector.py 的切分（train/val = 兩個 baseline 的 80/20，
#     test = 9 個含攻擊場景）。
#   * 兩個模型都只在「每場景第 WINDOW 行之後」的位置評分，索引集合完全相同。
#   * DeepLog 除了原本的 top-k 規則，額外輸出 surprisal = -log softmax(實際模板)，
#     與 n-gram 的分數同一個量綱 → PR-AUC / ROC-AUC 可直接比。
#   * 閾值一律取 val（未見過的正常資料）分數的 max，即零誤報操作點。
#   * 同樣做 seen-only 拆解（拿掉訓練集沒出現過的新模板），隔離洩漏。
#
# 反交錯（STREAM_KEY，見 ngram_detector.py 的說明）：
#   多組 pair 匯進同一份 log 時，檔案順序是多條流交錯的結果。本腳本把
#   ngram_detector.stream_key 的分流鍵一併套用到**兩個模型**，用來驗證
#   「反交錯是通用前處理」而不是 n-gram 的特例 —— LSTM 吃的是同一份序列，
#   如果它也同幅度受益，那這件事就與模型無關。
#   兩個模型永遠共用同一組切分與同一組評估位置，換 STREAM_KEY 也不例外。
#
# 執行： ml/venv/bin/python ml/compare_ngram_deeplog.py
#        STREAM_KEY=pair ml/venv/bin/python ml/compare_ngram_deeplog.py
# 輸出： ml/out/ngram_vs_deeplog.txt （STREAM_KEY!=none 時檔名加後綴）
# =============================================================================
import os

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (average_precision_score, roc_auc_score,
                             precision_recall_fscore_support, confusion_matrix)

from ngram_detector import (NGram, load, scenario_seq, split_segments,
                            stream_key, VAL_FRAC, ATTACKS,
                            SOURCE_FIELD, SOURCE_COL)
from deeplog import DeepLog, WINDOW, HIDDEN, LAYERS, EPOCHS, BATCH, TOPK, LR

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
torch.manual_seed(42)
np.random.seed(42)

BEST_N = 2   # ngram_detector.py 的橫向比較顯示 bigram 是甜蜜點


def windows(seq):
    """回傳 (X, y_next, 位置索引)；位置索引是相對該序列的 offset。"""
    X, y, idx = [], [], []
    for i in range(len(seq) - WINDOW):
        X.append(seq[i:i + WINDOW]); y.append(seq[i + WINDOW]); idx.append(i + WINDOW)
    return np.array(X), np.array(y), np.array(idx)


def report(emit, name, y, score, thr, typ, extra_pred=None, extra_name=""):
    ap = average_precision_score(y, score)
    auc = roc_auc_score(y, score)
    pred = (score >= thr).astype(int) if extra_pred is None else extra_pred
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    tag = f"（判定={extra_name}）" if extra_pred is not None else f"（thr={thr:.3f}）"
    emit(f"  {name} {tag}")
    emit(f"    PR-AUC={ap:.3f}  ROC-AUC={auc:.3f}")
    emit(f"    precision={p:.3f} recall={r:.3f} f1={f:.3f}  "
         f"TP={tp} FP={fp} FN={fn} TN={tn}  FPR={fp / max(tn + fp, 1):.4%}")
    rec = {}
    for at in ATTACKS:
        m = typ == at
        if m.sum():
            rec[at] = (int(pred[m].sum()), int(m.sum()))
    emit("    各類別 recall: " + "  ".join(
        f"[{k}] {v[0]}/{v[1]}={v[0] / v[1]:.0%}" for k, v in rec.items()))
    return dict(ap=ap, auc=auc, precision=p, recall=r, f1=f, fp=int(fp))


def main():
    df, vocab = load()
    V = len(vocab)
    log = []

    def emit(s=""):
        print(s); log.append(str(s))

    mode = os.environ.get("STREAM_KEY", "none").strip().lower()
    if mode not in ("none", "pair", "source"):
        raise SystemExit(f"STREAM_KEY 只能是 none/pair/source，收到 {mode!r}")

    emit("=" * 72)
    emit("n-gram (bigram) vs DeepLog(LSTM) —— 對齊切分與評估位置後的公平對照")
    emit("=" * 72)
    emit(f"反交錯 STREAM_KEY={mode}（兩個模型同時套用）")
    emit(f"分流鍵欄位 SOURCE_FIELD={SOURCE_FIELD} → {SOURCE_COL}")

    scen = sorted(df["scenario"].unique())
    base = [s for s in scen if "baseline" in s]
    test = [s for s in scen if s not in base]
    emit(f"訓練(純正常): {base}")
    emit(f"測試(含攻擊): {test}")

    # ---- 共用切分：先在場景層做時序切分，再各自分流成多條序列 ----
    train_seqs, val_seqs = [], []
    for s in base:
        sub = df[df.scenario == s]
        cut = int(len(sub) * (1 - VAL_FRAC))
        train_seqs += [q for q, _ in split_segments(sub.iloc[:cut], mode)]
        val_seqs   += [q for q, _ in split_segments(sub.iloc[cut:], mode)]
    emit(f"train={sum(len(x) for x in train_seqs)} 行   "
         f"val={sum(len(x) for x in val_seqs)} 行   "
         f"（兩個模型完全共用；序列 {len(train_seqs)}/{len(val_seqs)} 條）")

    # ---- 對齊評估位置：每條流各自跳過前 WINDOW 行（沒有足夠上下文）----
    # 分流後「開頭」有 N 個，每一條都要各自跳，否則 FP 會隨流數灌水。
    test_segs, eval_idx = [], []
    for s in test:
        for seq, idx in split_segments(df[df.scenario == s], mode):
            if len(seq) <= WINDOW:
                continue          # 太短的流（如零星 System 行）無法評分
            off = windows(seq)[2]
            test_segs.append((seq, off))
            eval_idx.append(idx[off])
    eval_idx = np.concatenate(eval_idx)
    y = df.loc[eval_idx, "label"].values.astype(int)
    typ = df.loc[eval_idx, "attack_type"].values
    sec = (df.loc[eval_idx, "scenario"].astype(str) + "|" +
           df.loc[eval_idx, "ts_sec"].astype(str)).values
    emit(f"對齊後評估位置: {len(eval_idx)} 行（每條流各自跳過前 {WINDOW} 行，"
         f"共 {len(test_segs)} 條），異常 {int(y.sum())} 行")

    # =====================================================================
    # 1) bigram
    # =====================================================================
    ng = NGram(BEST_N, V)
    for s in train_seqs:
        ng.fit_seq(s)
    val_ng = np.concatenate([ng.surprisal(s)[0][WINDOW:] for s in val_seqs
                             if len(s) > WINDOW])
    thr_ng = float(val_ng.max())

    parts = [ng.surprisal(seq)[0][off] for seq, off in test_segs]
    score_ng = np.concatenate(parts)

    # =====================================================================
    # 2) DeepLog：同一份 train 重訓，額外輸出 surprisal
    # =====================================================================
    Xtr, ytr = [], []
    for s in train_seqs:
        X, yy, _ = windows(s)
        if len(X):
            Xtr.append(X); ytr.append(yy)
    Xtr = np.concatenate(Xtr); ytr = np.concatenate(ytr)
    emit(f"\nDeepLog 訓練視窗數: {len(Xtr)}（與 n-gram 同一份 train 序列）")

    model = DeepLog(V, HIDDEN, LAYERS)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    lossf = nn.CrossEntropyLoss()
    ds = TensorDataset(torch.tensor(Xtr, dtype=torch.long),
                       torch.tensor(ytr, dtype=torch.long))
    dl = DataLoader(ds, batch_size=BATCH, shuffle=True)
    model.train()
    for ep in range(EPOCHS):
        tot = 0.0
        for xb, yb in dl:
            opt.zero_grad()
            loss = lossf(model(xb), yb)
            loss.backward(); opt.step()
            tot += loss.item() * len(xb)
        emit(f"  epoch {ep + 1:2d}/{EPOCHS}  loss={tot / len(ds):.4f}")
    model.eval()

    def dl_score(seq):
        """回傳 (surprisal, topk_miss)，長度 = len(seq)-WINDOW。"""
        X, yn, _ = windows(seq)
        if len(X) == 0:
            return np.array([]), np.array([], dtype=bool)
        with torch.no_grad():
            logits = model(torch.tensor(X, dtype=torch.long))
            logp = torch.log_softmax(logits, dim=1).numpy()
            topk = torch.topk(logits, TOPK, dim=1).indices.numpy()
        sur = -logp[np.arange(len(yn)), yn]
        miss = np.array([yn[i] not in topk[i] for i in range(len(yn))])
        return sur, miss

    val_dl = np.concatenate([d for d in (dl_score(s)[0] for s in val_seqs) if len(d)])
    thr_dl = float(val_dl.max())

    sur_parts, miss_parts = [], []
    for seq, _ in test_segs:
        sur, miss = dl_score(seq)
        sur_parts.append(sur); miss_parts.append(miss)
    score_dl = np.concatenate(sur_parts)
    miss_dl = np.concatenate(miss_parts).astype(int)

    # =====================================================================
    # 報告
    # =====================================================================
    tids = df.loc[eval_idx, "tid"].values
    seen = np.array([t in ng.seen_uni for t in tids])

    emit()
    emit("-" * 72)
    emit("(A) 全量（含訓練集沒出現過的新模板 —— 有洩漏）")
    emit("-" * 72)
    a_ng = report(emit, f"bigram (n={BEST_N})", y, score_ng, thr_ng, typ)
    a_dl = report(emit, "DeepLog surprisal", y, score_dl, thr_dl, typ)
    report(emit, "DeepLog top-k 規則", y, score_dl, thr_dl, typ,
           extra_pred=miss_dl, extra_name=f"不在 top-{TOPK}")

    emit()
    emit("-" * 72)
    emit("(B) seen-only（只留目標模板訓練集見過的行 —— 隔離洩漏）")
    emit("-" * 72)
    emit(f"    保留 {int(seen.sum())}/{len(seen)} 行，異常 {int(y[seen].sum())} 行")
    b_ng = report(emit, f"bigram (n={BEST_N})", y[seen], score_ng[seen], thr_ng, typ[seen])
    b_dl = report(emit, "DeepLog surprisal", y[seen], score_dl[seen], thr_dl, typ[seen])
    report(emit, "DeepLog top-k 規則", y[seen], score_dl[seen], thr_dl, typ[seen],
           extra_pred=miss_dl[seen], extra_name=f"不在 top-{TOPK}")

    emit()
    emit("-" * 72)
    emit("(C) 逐秒聚合（每秒取 max 分數，對齊專案的「注入秒」口徑）")
    emit("-" * 72)
    g = pd.DataFrame({"k": sec, "y": y, "ng": score_ng, "dl": score_dl}) \
        .groupby("k").agg(y=("y", "max"), ng=("ng", "max"), dl=("dl", "max"))
    for nm, col, th in [(f"bigram (n={BEST_N})", "ng", thr_ng),
                        ("DeepLog surprisal", "dl", thr_dl)]:
        s_, y_ = g[col].values, g["y"].values
        pred = (s_ >= th).astype(int)
        p, r, f, _ = precision_recall_fscore_support(y_, pred, average="binary",
                                                     zero_division=0)
        tn, fp, fn, tp = confusion_matrix(y_, pred, labels=[0, 1]).ravel()
        emit(f"  {nm}: PR-AUC={average_precision_score(y_, s_):.3f}  "
             f"precision={p:.3f} recall={r:.3f} f1={f:.3f}  "
             f"TP={tp} FP={fp} FN={fn}")

    emit()
    emit("=" * 72)
    emit("結論表（line-level PR-AUC）")
    emit("=" * 72)
    emit(f"{'模型':<22} | {'全量':>8} | {'seen-only':>10}")
    emit("-" * 48)
    emit(f"{'bigram (零訓練, 數頻率)':<22} | {a_ng['ap']:>8.3f} | {b_ng['ap']:>10.3f}")
    emit(f"{'DeepLog (LSTM, 15 epoch)':<22} | {a_dl['ap']:>8.3f} | {b_dl['ap']:>10.3f}")

    sfx = "" if mode == "none" else f"_{mode}"
    if SOURCE_FIELD == "sourcenode":
        sfx += "_sourcenode"
    with open(os.path.join(OUT, f"ngram_vs_deeplog{sfx}.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {OUT}/ngram_vs_deeplog{sfx}.txt")


if __name__ == "__main__":
    main()
