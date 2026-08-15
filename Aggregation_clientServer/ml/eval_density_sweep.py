#!/usr/bin/env python3
# =============================================================================
# eval_density_sweep.py ── 【實驗2】攻擊密度 vs 偵測率 曲線
# =============================================================================
# 搭配 collect_density_sweep.sh 的產物。場景命名：
#   densitysweep_baseline_<stamp>        純正常，定閾值/訓練用
#   densitysweep_d<N>_r<r>_<stamp>       密度 N（每 300s 每類注入 N 筆）第 r 輪
#
# ⚠ 方法學鐵律（collect 腳本已強調，這裡強制執行）：
#   PR-AUC 的 no-skill 基線 = 正例比例本身，密度一變 PR-AUC 自動移動。
#   因此曲線的 **y 軸主軸** 是與基線無關的量：
#     (a) 逐秒 recall @ 零誤報閾值   —— 閾值固定在 baseline val 的 max，不隨密度動
#     (b) 逐秒 FP 數                 —— 絕對誤報，與密度無關
#     (c) lift = PR-AUC ÷ 正例比例   —— 把基線效應除掉後的「相對於亂猜的倍數」
#   PR-AUC 絕對值也印出來，但只作參考、**不可**跨密度比大小當偵測力變化。
#
# x 軸：實測的逐秒正例比例（由資料統計，不手算）。
#
# 執行： ml/venv/bin/python ml/eval_density_sweep.py
# 輸出： ml/out/density_sweep.txt / .csv / .png（若有 matplotlib）
# =============================================================================
import os
import re
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

from ngram_detector import NGram, scenario_seq, VAL_FRAC

BEST_N = 2   # bigram（ngram_detector 的橫向比較顯示是甜蜜點）

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

DENSITY_RE = re.compile(r"densitysweep_d(\d+)_r\d+")


def load_sweep():
    """只載入 densitysweep_* 場景，重建 tid（詞彙以這批資料為準）。"""
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    df = df[df["scenario"].str.startswith("densitysweep_")].copy()
    if df.empty:
        raise SystemExit("找不到 densitysweep_* 場景，請先跑 ml/collect_density_sweep.sh "
                         "+ ml/parse_logs.py")
    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].astype(str).unique()))}
    df["tid"] = df["template_id"].astype(str).map(vocab)
    df = df.sort_values(["scenario", "seq_pos"]).reset_index(drop=True)
    return df, len(vocab)


def sec_aggregate(sub, score):
    """把逐行 (label, score) 依秒聚合：label 取 max、score 取 max。回傳 (y_sec, s_sec)。"""
    g = pd.DataFrame({"k": sub["ts_sec"].values, "y": sub["label"].values, "s": score}) \
        .groupby("k").agg(y=("y", "max"), s=("s", "max"))
    return g["y"].values, g["s"].values


def main():
    df, V = load_sweep()
    log = []

    def emit(s=""):
        print(s); log.append(str(s))

    emit("=" * 72)
    emit("【實驗2】攻擊密度 vs 偵測率")
    emit("=" * 72)
    emit(f"詞彙量 V={V}  bigram n={BEST_N}")

    base = [s for s in df["scenario"].unique() if s.startswith("densitysweep_baseline")]
    if not base:
        raise SystemExit("缺 densitysweep_baseline 場景（定閾值用）")

    # ---- 訓練 bigram + 定零誤報閾值（baseline 切 train/val）----
    model = NGram(BEST_N, V)
    val_scores = []
    for s in base:
        seq, _ = scenario_seq(df, s)
        cut = int(len(seq) * (1 - VAL_FRAC))
        model.fit_seq(seq[:cut])
        sc, _, _ = model.surprisal(seq[cut:])
        val_scores.append(sc)
    val_scores = np.concatenate(val_scores)
    thr = float(val_scores.max())
    emit(f"baseline 定閾值：val max = {thr:.3f}（零誤報操作點）")

    # ---- 依密度 N 分組 ----
    groups = defaultdict(list)
    for s in df["scenario"].unique():
        m = DENSITY_RE.match(s)
        if m:
            groups[int(m.group(1))].append(s)

    if not groups:
        raise SystemExit("沒有 densitysweep_d<N>_r<r> 場景")

    def metrics(y, score):
        """回傳 (正例率, recall@0FP, FP數, PR-AUC, lift)。"""
        pred = (score >= thr).astype(int)
        r = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)[1]
        fp = int(((pred == 1) & (y == 0)).sum())
        ap = average_precision_score(y, score) if y.sum() else float("nan")
        pos = y.mean()
        return pos, r, fp, ap, (ap / pos if pos > 0 else float("nan"))

    rows = []
    emit()
    emit("每個密度點兩個層級都報：行級(使用者指定的『異常比例』單位) + 秒級(評估單位)。")
    emit("⚠ recall@0FP / FP / lift 與基線無關，可跨密度比；PR-AUC 絕對值不可比大小。")
    emit()
    emit(f"{'密度N':>5} | {'層級':>4} | {'正例率':>7} | {'recall@0FP':>10} | "
         f"{'FP':>5} | {'PR-AUC':>7} | {'lift':>6}")
    emit("-" * 62)
    for N in sorted(groups):
        # 逐行分數（行級）+ 逐秒聚合（秒級）
        yl, sl, ys, ss = [], [], [], []
        for s in groups[N]:
            sub = df[df["scenario"] == s].sort_values("seq_pos")
            sc, _, _ = model.surprisal(sub["tid"].values)
            yl.append(sub["label"].values.astype(int)); sl.append(sc)
            y_sec, s_sec = sec_aggregate(sub, sc)
            ys.append(y_sec); ss.append(s_sec)
        yl = np.concatenate(yl); sl = np.concatenate(sl)
        ysec = np.concatenate(ys); ssec = np.concatenate(ss)

        lp, lr, lfp, lap, llift = metrics(yl, sl)       # 行級
        sp, sr, sfp, sap, slift = metrics(ysec, ssec)   # 秒級
        emit(f"{N:>5} | {'行級':>4} | {lp:>7.2%} | {lr:>10.2%} | {lfp:>5} | {lap:>7.3f} | {llift:>6.2f}")
        emit(f"{'':>5} | {'秒級':>4} | {sp:>7.2%} | {sr:>10.2%} | {sfp:>5} | {sap:>7.3f} | {slift:>6.2f}")
        rows.append(dict(density_N=N,
                         line_pos_rate=lp, line_recall_0fp=lr, line_fp=lfp, line_pr_auc=lap, line_lift=llift,
                         sec_pos_rate=sp, sec_recall_0fp=sr, sec_fp=sfp, sec_pr_auc=sap, sec_lift=slift))

    res = pd.DataFrame(rows)
    res.to_csv(os.path.join(OUT, "density_sweep.csv"), index=False)

    emit()
    emit("=" * 72)
    emit("解讀")
    emit("=" * 72)
    emit("- 主軸看 recall@0FP 與逐秒FP：若 recall 隨密度上升而『穩定』、FP 不爆，")
    emit("  代表偵測力對密度穩健；若 recall 只在高密度才好，代表低密度(接近真實)偏弱。")
    emit("- lift 把基線效應除掉：lift 遠大於 1 才代表真的比亂猜強。")
    emit("- ⚠ PR-AUC 絕對值僅供參考，跨密度比大小無意義（基線 = 正例率本身）。")

    with open(os.path.join(OUT, "density_sweep.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(str(x) for x in log) + "\n")

    # ---- 圖（≥2 個密度點才畫曲線；單點只印表）----
    try:
        if len(res) < 2:
            raise RuntimeError("只有單一密度點，曲線需 ≥2 點；略過畫圖")
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        x = res["line_pos_rate"] * 100
        fig, ax1 = plt.subplots(figsize=(7, 4.5))
        ax1.plot(x, res["line_recall_0fp"] * 100, "o-", color="#2c7fb8", label="行級 recall @ 零誤報")
        ax1.set_xlabel("行級攻擊正例比例 (%)")
        ax1.set_ylabel("recall @ 零誤報 (%)", color="#2c7fb8")
        ax1.set_ylim(0, 105)
        ax1.tick_params(axis="y", labelcolor="#2c7fb8")
        ax2 = ax1.twinx()
        ax2.plot(x, res["line_fp"], "s--", color="#de2d26", label="行級 FP 數")
        ax2.set_ylabel("行級 FP 數", color="#de2d26")
        ax2.tick_params(axis="y", labelcolor="#de2d26")
        fig.suptitle("攻擊密度 vs 偵測率（bigram, 零誤報操作點）")
        fig.tight_layout()
        fig.savefig(os.path.join(OUT, "density_sweep.png"), dpi=130)
        emit(f"圖已存: {OUT}/density_sweep.png")
    except Exception as e:
        emit(f"（跳過畫圖：{e}）")

    print(f"\n報告: {OUT}/density_sweep.txt")
    print(f"表格: {OUT}/density_sweep.csv")


if __name__ == "__main__":
    main()
