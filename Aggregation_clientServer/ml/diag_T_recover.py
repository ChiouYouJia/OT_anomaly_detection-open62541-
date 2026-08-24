#!/usr/bin/env python3
# =============================================================================
# diag_T_recover.py ── 全量 + 多門檻，看 mvdeeplog 到底能「撿回」多少 T
# =============================================================================
# 問題：mvdeeplog 的 tmpl 分量在全量 p99.9 下 T=0/216，但離散 n-gram 全量 T=100%。
#   T 的模板 T8d2c08(BadUserAccessDenied) 在 baseline 出現 0 次(全新模板)。
#   → 想知道：神經 tmpl surprisal 把 T 排在分佈哪裡？放寬門檻能撿回多少？
#     benign 的 System 連線日誌流是不是把門檻墊高了？
#
# 作法：完全重用 mvdeeplog 的資料管線與模型(import)，訓練 tmpl+dt+val，
#   然後對 tmpl 分量 / sum 聚合 / max 聚合，報多門檻(p99.9/p99/p95/p90)的
#   逐類 recall 與 benign 誤報率，並印 T 的分數百分位、benign System 流的分數百分位。
#
# 執行：SCENARIO_FILTER=topo3 ml/venv/bin/python ml/diag_T_recover.py
# 輸出：ml/out/diag_T_recover.txt
# =============================================================================
import os, sys
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "out")
torch.set_num_threads(int(os.environ.get("TORCH_THREADS", "4")))

import mvdeeplog as M
from ngram_detector import split_segments, VAL_FRAC, SOURCE_COL, stream_key

SCENARIO_FILTER = os.environ.get("SCENARIO_FILTER", "topo3").strip()
STREAM_MODE = os.environ.get("STREAM_KEY", "pair").strip()
MODE = "tmpl+dt+val"

log = []
def emit(s=""):
    print(s, flush=True); log.append(str(s))


def zscore_ref(comp, ref):
    """把各分量用 benign 的 median / (p99-median) 標準化（同 diagnose 的 max 口徑）。"""
    zs = {}
    for k, (med, scale) in ref.items():
        x = np.nan_to_num(comp[k], nan=0.0)
        zs[k] = (x - med) / scale
    return zs


def main():
    emit("讀取 parsed_all.csv …")
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    df = df[df.scenario.str.contains(SCENARIO_FILTER, na=False)]
    df = df.sort_values(["scenario", "seq_pos"]).reset_index(drop=True)
    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].unique()))}
    df["tid"] = df["template_id"].map(vocab)
    V = len(vocab)
    emit(f"讀入 {len(df)} 行  詞彙量 V={V}")

    scen = list(df.scenario.unique())
    base_scen = [s for s in scen if "baseline" in s]
    test_scen = [s for s in scen if "baseline" not in s]

    tr_segs, va_segs = [], []
    for s in base_scen:
        sub = df[df.scenario == s]
        cut = int(len(sub) * (1 - VAL_FRAC))
        tr_segs += split_segments(sub.iloc[:cut], STREAM_MODE)
        va_segs += split_segments(sub.iloc[cut:], STREAM_MODE)
    te_segs = [sg for s in test_scen
               for sg in split_segments(df[df.scenario == s], STREAM_MODE)]

    tr_idx = np.concatenate([i for _, i in tr_segs])
    tv = df.loc[tr_idx, "dist"].values.astype(float)
    tv = tv[np.isfinite(tv)]
    norm = (float(tv.mean()), float(tv.std() + 1e-9))

    Wtr = M.segments_to_windows(df, tr_segs, norm)
    Wva = M.segments_to_windows(df, va_segs, norm)
    Wte = M.segments_to_windows(df, te_segs, norm)

    pos = Wte[7]
    y = df.loc[pos, "label"].values.astype(int)
    typ = df.loc[pos, "attack_type"].values
    role = df.loc[pos, "role"].values
    emit(f"訓練視窗 {len(Wtr[0])}  測試視窗 {len(Wte[0])}  異常 {int(y.sum())} "
         f"{dict(pd.Series(typ[y==1]).value_counts())}")

    emit("\n訓練 mvdeeplog (tmpl+dt+val) …")
    torch.manual_seed(M.SEED); np.random.seed(M.SEED)
    model = M.MVDeepLog(V, Wtr[2].shape[2])
    # 靜音 mvdeeplog 內部 train 的逐 epoch 輸出，改用自己的
    _orig_emit = M.emit
    M.emit = lambda *a, **k: None
    M.train(model, Wtr, MODE)
    cva, _ = M.score(model, Wva, MODE)
    _, ref_sum = M.combine(cva, MODE)            # sum 聚合用的 median/IQR
    cte, _ = M.score(model, Wte, MODE)
    M.emit = _orig_emit

    # sum 聚合分數（headline 用的）
    s_sum, _ = M.combine(cte, MODE, ref_sum)

    # max 聚合：用 benign(=val) 的 median / (p99-median) 標準化後取 max（同 diagnose c）
    ref_z = {}
    for k in ["tmpl", "dt", "val"]:
        g = cva[k][np.isfinite(cva[k])]
        med = float(np.median(g)); p99 = float(np.percentile(g, 99))
        ref_z[k] = (med, max(p99 - med, 1e-6))
    zte = zscore_ref(cte, ref_z)
    s_max = np.max(np.stack([zte[k] for k in ["tmpl", "dt", "val"]]), axis=0)

    tmpl = np.nan_to_num(cte["tmpl"], nan=0.0)

    # ---- 1) T 在各分數分佈的位置 -----------------------------------------
    emit("\n" + "=" * 74)
    emit("1) T(216 行) 的分數落在 benign 分佈的哪裡？（百分位；越接近 100 越可分）")
    emit("=" * 74)
    benign = y == 0
    Tm = typ == "T"
    for name, sc in [("tmpl 分量", tmpl), ("sum 聚合", s_sum), ("max 聚合", s_max)]:
        bs = sc[benign]
        # T 分數的中位，換算成「benign 中有多少比例低於它」= 百分位
        t_med = np.median(sc[Tm])
        pct = (bs < t_med).mean() * 100
        emit(f"  {name:<10} T 分數中位={t_med:8.3f}   ＝ benign 的第 {pct:5.1f} 百分位"
             f"   (benign p90={np.percentile(bs,90):.3f} p99={np.percentile(bs,99):.3f} "
             f"p99.9={np.percentile(bs,99.9):.3f} max={bs.max():.3f})")

    # ---- 2) benign System 流是否墊高門檻 ---------------------------------
    emit("\n" + "=" * 74)
    emit("2) benign 各 role 的 tmpl surprisal —— System 連線日誌流是否本就高？")
    emit("=" * 74)
    for r in ["Sensor", "Motor", "System", "App"]:
        m = benign & (role == r)
        if not m.sum():
            continue
        x = tmpl[m]
        emit(f"  {r:<8} n={int(m.sum()):>6}  median={np.median(x):7.3f}  "
             f"p99={np.percentile(x,99):7.3f}  p99.9={np.percentile(x,99.9):7.3f}  max={x.max():7.3f}")
    emit(f"  → 全 benign tmpl p99.9 門檻 = {np.percentile(tmpl[benign],99.9):.3f}")
    emit(f"    T 的 tmpl surprisal: median={np.median(tmpl[Tm]):.3f} "
         f"min={tmpl[Tm].min():.3f} max={tmpl[Tm].max():.3f}")

    # ---- 3) 多門檻逐類 recall + benign 誤報率 ----------------------------
    emit("\n" + "=" * 74)
    emit("3) 放寬門檻能撿回多少 T？（全量；各門檻由 benign 分位定，附 benign 誤報率）")
    emit("=" * 74)
    for name, sc in [("tmpl 分量", tmpl), ("sum 聚合", s_sum), ("max 聚合", s_max)]:
        emit(f"\n  【{name}】  PR-AUC={average_precision_score(y,sc):.3f}  "
             f"ROC-AUC={roc_auc_score(y,sc):.3f}")
        emit(f"    {'門檻':<10}{'benign誤報':>10}{'  逐類 recall(S/T/R/RP)'}")
        for q in [99.9, 99.5, 99.0, 97.0, 95.0, 90.0]:
            thr = np.percentile(sc[benign], q)
            fp = (sc[benign] >= thr).mean() * 100
            cells = []
            for a in ["S", "T", "R", "RP"]:
                ma = typ == a
                if ma.sum():
                    cells.append(f"{a} {int(((sc>=thr)&ma).sum())}/{int(ma.sum())}")
            emit(f"    p{q:<9}{fp:>9.2f}%   " + "  ".join(cells))

    p = os.path.join(OUT, "diag_T_recover.txt")
    open(p, "w", encoding="utf-8").write("\n".join(log) + "\n")
    emit(f"\n報告已存: {p}")


if __name__ == "__main__":
    main()
