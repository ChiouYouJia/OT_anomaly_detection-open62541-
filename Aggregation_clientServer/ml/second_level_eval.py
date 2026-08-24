#!/usr/bin/env python3
# =============================================================================
# second_level_eval.py ── 由各模型之逐行分數，計算「逐秒（second-level）」指標
# =============================================================================
# 逐秒聚合：以 (scenario, ts_sec) 分組，每一秒
#     y_sec = max(label)（該秒含任一異常行即為異常秒）
#     s_sec = max(score)（該秒之最大分數）
#
# 運作點（2026-08-24 改）：門檻取自 **val 集**（baseline 場景之後 20%，模型訓練
#   期間完全未使用）之正常秒分數百分位，再套用到評估集。
#
#   為什麼要改：舊版門檻取自「評估集之正常秒」（np.percentile(s[y==0], op)）。
#   那樣所報告的誤報率必然等於設計值 —— p99.9 一定得到 0.1% —— 因為門檻就是那樣
#   定義出來的。那不是量測結果，是恆等式；而且門檻參數接觸了評估資料，逐類召回
#   與精確率都帶樂觀偏差。改用 val 校準後，「設計誤報率」與「實際誤報率」是兩個
#   不同的數，兩者的落差本身就是結果（見報表的 設計FP / 實測FP 兩欄）。
#
# 逐類 recall：型別 a 之「正例秒」= 含任一 a 型行之秒；recall_a = 該類秒被偵得之比例。
#
# 輸入分數檔（測試：含 scenario, ts_sec, label, attack_type, <score>）
#             （val ：含 scenario, ts_sec, <score>，由各模型 DUMP_SCORES=1 產生）
#
# 執行：ml/venv/bin/python ml/second_level_eval.py   → out/second_level_eval.txt
# =============================================================================
import os
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
TYPES = ["S", "T", "R", "RP"]
OPS = [99.9, 99.5]

log = []
def emit(s=""):
    print(s); log.append(str(s))


def to_seconds(df, score_col, has_label=True):
    """逐秒聚合，回傳 (sec DataFrame, 每型別之正例秒索引 dict)。"""
    df = df.dropna(subset=[score_col]).copy()
    key = ["scenario", "ts_sec"]
    agg = {"s": (score_col, "max")}
    if has_label:
        agg["y"] = ("label", "max")
    sec = df.groupby(key).agg(**agg)
    pos_idx = {}
    if has_label:
        for a in TYPES:
            sub = df[df["attack_type"] == a]
            pos_idx[a] = sub.groupby(key).size().index if len(sub) else None
    return sec, pos_idx


def metrics_at(sec, pos_idx, thr):
    """給定門檻，回傳 (實測FPR%, Prec, Recall, F1, 逐類命中字串)。"""
    y = sec["y"].values.astype(int)
    s = sec["s"].values.astype(float)
    pred = s >= thr
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int(((~pred) & (y == 1)).sum())
    P = tp / (tp + fp) if tp + fp else 0.0
    R = tp / (tp + fn) if tp + fn else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    fpr = fp / max((y == 0).sum(), 1) * 100
    per = []
    for a in TYPES:
        idx = pos_idx.get(a)
        if idx is None or len(idx) == 0:
            continue
        per.append(f"{a} {int((sec.loc[idx, 's'] >= thr).sum())}/{len(idx)}")
    return fpr, P, R, F, "  ".join(per)


def report(name, sec, pos_idx, val_sec):
    y = sec["y"].values.astype(int)
    s = sec["s"].values.astype(float)
    emit(f"\n{'='*78}\n【{name}】逐秒：總秒={len(sec)}  異常秒={int(y.sum())}  "
         f"PR-AUC={average_precision_score(y, s):.3f}  "
         f"ROC-AUC={roc_auc_score(y, s):.3f}\n{'='*78}")

    # ── 協定 A：匹配誤報率（門檻取自評估集正常秒）─────────────────────────
    # 定位：跨模型「等誤報」比較。所報誤報率等於設計值乃由定義保證，故此表僅可
    #       作為同一資料集內之相對比較，不得詮釋為部署效能估計。
    emit("  [協定 A] 匹配誤報率 —— 門檻取自評估集正常秒，用於跨模型等誤報比較")
    emit(f"    {'運作點':<9}{'實測FP':>8}{'Prec':>8}{'Recall':>8}{'F1':>7}"
         f"   逐類 recall（秒）")
    for op in OPS:
        thr = float(np.percentile(s[y == 0], op))
        fpr, P, R, F, per = metrics_at(sec, pos_idx, thr)
        emit(f"    p{op:<8g}{fpr:>7.2f}%{P:>8.3f}{R:>8.3f}{F:>7.3f}   {per}")

    # ── 協定 B：val 校準（部署情境模擬）───────────────────────────────────
    if val_sec is None:
        emit("  [協定 B] 缺 val 分數檔 —— 請以 DUMP_SCORES=1 重跑該模型。")
        return
    vs = val_sec["s"].values.astype(float)
    nuniq = len(np.unique(vs))
    emit(f"  [協定 B] val 校準 —— 門檻僅由 val 決定（{len(vs)} 個正常秒，"
         f"{nuniq} 個相異值）")
    if nuniq < 50:
        emit(f"    ⚠ 分數高度離散（僅 {nuniq} 個相異值）：百分位門檻易落於機率質點上，"
             f"此時實測誤報率不可解釋")
    emit(f"    ⚠ p99.9 之估計僅由 val 前 {len(vs)*0.001:.1f} 個樣本決定，抽樣變異極大")
    emit(f"    {'運作點':<9}{'設計FP':>8}{'實測FP':>8}{'Prec':>8}{'Recall':>8}{'F1':>7}"
         f"   逐類 recall（秒）")
    for op in OPS:
        thr = float(np.percentile(vs, op))
        fpr, P, R, F, per = metrics_at(sec, pos_idx, thr)
        tie = int((vs == thr).sum())
        flag = f"  ← 門檻落於 {tie} 個 val 秒共用之質點" if tie > 0.01 * len(vs) else ""
        emit(f"    p{op:<8g}{100-op:>7.1f}%{fpr:>7.2f}%{P:>8.3f}{R:>8.3f}{F:>7.3f}"
             f"   {per}{flag}")


def main():
    # (顯示名, 測試分數檔, 測試欄, val 分數檔, val 欄)
    jobs = [
        ("預測式 LSTM (mvDeepLog)", "mvdeeplog_scores_topo3.csv", "score",
         "mvdeeplog_valscores_topo3.csv", "score"),
        ("DeepLog (僅模板)", "mvdeeplog_scores_deeplog.csv", "score",
         "mvdeeplog_valscores_deeplog.csv", "score"),
        ("重建式 LSTM-AE", "mvlstm_ae_scores_fix.csv", "score",
         "mvlstm_ae_valscores_fix.csv", "score"),
        ("n-gram bigram", "ngram_scores_pair.csv", "ngram2",
         "ngram_valscores_pair.csv", "ngram2"),
    ]
    emit("逐秒（second-level）評估 —— 兩種運作點協定並列")
    emit("  協定 A 匹配誤報率：門檻取自評估集正常秒。跨模型等誤報比較用；所報誤報率")
    emit("        由定義保證，不得詮釋為部署效能。")
    emit("  協定 B val 校準：門檻僅由 val（baseline 後 20%，訓練期未使用）決定。")
    emit("        設計FP = 名目值；實測FP = 該門檻在評估集正常秒上量到的實際值。")
    for name, fn, col, vfn, vcol in jobs:
        path = os.path.join(OUT, fn)
        if not os.path.exists(path):
            emit(f"\n[skip] 缺分數檔：{fn}")
            continue
        df = pd.read_csv(path, low_memory=False)
        if col not in df.columns:
            emit(f"\n[skip] {fn} 無欄位 {col}")
            continue
        sec, pos_idx = to_seconds(df, col)

        val_sec = None
        vpath = os.path.join(OUT, vfn)
        if os.path.exists(vpath):
            vdf = pd.read_csv(vpath, low_memory=False)
            if vcol in vdf.columns:
                val_sec, _ = to_seconds(vdf, vcol, has_label=False)
        report(name, sec, pos_idx, val_sec)

    p = os.path.join(OUT, "second_level_eval.txt")
    open(p, "w", encoding="utf-8").write("\n".join(log) + "\n")
    print(f"\n報告已存: {p}")


if __name__ == "__main__":
    main()
