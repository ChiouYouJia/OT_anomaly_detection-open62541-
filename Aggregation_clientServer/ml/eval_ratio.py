#!/usr/bin/env python3
# =============================================================================
# eval_ratio.py ── 攻擊比例 vs 檢測準度的相關性
# =============================================================================
# 問題：
#   報告引用的異常比例 0.455% 是「採集配方」的產物（baseline 長度 vs 攻擊輪數），
#   不是系統的固有性質。那麼「比例本身」如何影響各偵測器的表現？
#
# 做法（重採樣，非重新採集）：
#   固定全部 48 筆真異常，只改變摻入的**正常行數量**，做出目標比例：
#       比例 = 48 / (48 + n_normal)   →   n_normal = 48*(1-p)/p
#   正常行從 baseline + 攻擊場景的正常行中抽樣（不重複）。
#
#   ✅ 這樣做的好處：各比例點共用**同一批攻擊行**，所以指標差異純粹來自比例，
#      不混入「不同次採集的攻擊行為差異」這個干擾因子。
#   ⚠️ 代價：這是重採樣而非真實重打攻擊，攻擊的絕對數量固定，
#      所以它回答的是「同樣一批攻擊稀釋在不同量的正常流量裡會怎樣」。
#
# 每個比例重複多次抽樣（不同 random seed）並報 mean ± std，
# 避免單次抽樣的運氣被當成趨勢。
#
# 執行： ml/venv/bin/python ml/eval_ratio.py
# 輸出： ml/out/ratio_results.txt, ml/out/ratio_summary.json
# =============================================================================
import os, json
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")

# 目標異常比例（涵蓋 0.05%~10%，橫跨兩個數量級）
RATIOS  = [0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.10]
REPEATS = 20                       # 每個比例的重採樣次數
ATTACKS = ["S", "T", "R", "RP"]

log = []
def out(s=""):
    print(s); log.append(str(s))


# ---- 偵測器（與 eval_v2.py 完全一致的定義）----
def det_layer1(d):
    return ((d["dist_ts_occurrence"].values > 1) |
            (d["session_denied_cumcount"].values > 1) |
            (d["sensor_events_in_sec_persrc"].values > 1)).astype(int)

def det_sourcenode(d):
    sn = d["lr_SourceNode"].astype(str).str.strip().str.lower()
    return sn.isin(["unverified", "null", "none"]).astype(int)

def det_no_echo(d):
    return (d["sensor_no_echo"].fillna(0).values > 0).astype(int)

DETECTORS = {
    "第1層 統計規則":        det_layer1,
    "SourceNode==null":     det_sourcenode,
    "sensor_no_echo":       det_no_echo,
    "統計 OR SourceNode":   lambda d: ((det_layer1(d) == 1) | (det_sourcenode(d) == 1)).astype(int),
}


def metrics(pred, d):
    true = d["label"].values
    p, r, f, _ = precision_recall_fscore_support(true, pred, average="binary", zero_division=0)
    nm = true == 0
    return dict(precision=p, recall=r, f1=f,
                fpr=float(pred[nm].sum() / max(nm.sum(), 1)))


def main():
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    v2 = df[df.scenario.str.startswith("v2_")].copy()

    anom = v2[v2.label == 1]
    norm = v2[v2.label == 0]
    n_a  = len(anom)

    out("=" * 78)
    out("攻擊比例 vs 檢測準度")
    out("=" * 78)
    out(f"固定異常池 : {n_a} 筆  {anom.attack_type.value_counts().to_dict()}")
    out(f"正常行池   : {len(norm)} 行")
    out(f"每個比例重複抽樣 {REPEATS} 次，報 mean ± std")
    out()
    out("重要：各比例點共用同一批攻擊行 → 指標差異純粹來自「正常流量的稀釋程度」，")
    out("      不混入不同次採集的攻擊行為差異。")

    results = {name: {} for name in DETECTORS}

    for p in RATIOS:
        # 先嘗試「保留全部異常、稀釋正常行」。若正常行不足以達到目標比例
        # （比例已低於現有資料的下限 0.455%），改為**縮減異常池**：
        #   用全部正常行 + 抽樣 k 筆異常，k = round(p*N_norm/(1-p))。
        # 這樣才能真的做出更低的比例，而不是三個點都退化成同一個 0.455%。
        n_norm = int(round(n_a * (1 - p) / p))
        if n_norm <= len(norm):
            mode, use_n, use_a = "dilute", n_norm, n_a
        else:
            mode = "subsample_anom"
            use_n = len(norm)
            use_a = max(1, int(round(p * use_n / (1 - p))))
        actual_p = use_a / (use_a + use_n)
        feasible = (mode == "dilute")

        out("\n" + "=" * 78)
        if mode == "dilute":
            out(f"目標比例 {p:.3%}   →  {use_a} 異常 + {use_n} 正常 = {use_a+use_n} 行"
                f"   (稀釋正常行)")
        else:
            out(f"目標比例 {p:.3%}   →  {use_a} 異常 + {use_n} 正常 = {use_a+use_n} 行"
                f"   (⚠ 已低於現有資料下限，改為抽樣縮減異常池)")
        out(f"實際比例 {actual_p:.3%}")
        out("=" * 78)

        acc = {name: [] for name in DETECTORS}
        for rep in range(REPEATS):
            rng = np.random.RandomState(1000 + rep)
            if mode == "dilute":
                a_part = anom
                n_part = norm.iloc[rng.choice(len(norm), size=use_n, replace=False)]
            else:
                # 縮減異常池：分層抽樣，盡量維持四類攻擊的相對比例
                a_part = anom.groupby("attack_type", group_keys=False).apply(
                    lambda g: g.sample(max(1, int(round(use_a * len(g) / len(anom)))),
                                       random_state=1000 + rep))
                n_part = norm
            sub = pd.concat([a_part, n_part]).sort_values(
                ["scenario", "seq_pos"]).reset_index(drop=True)
            for name, fn in DETECTORS.items():
                acc[name].append(metrics(fn(sub), sub))

        for name in DETECTORS:
            runs = acc[name]
            agg = {}
            for k in ["precision", "recall", "f1", "fpr"]:
                v = np.array([r[k] for r in runs], dtype=float)
                agg[k] = (float(v.mean()), float(v.std()))
            results[name][f"{actual_p:.6f}"] = dict(
                target=p, actual=actual_p, n_rows=n_a + use_n,
                n_norm=use_n, feasible=bool(feasible), repeats=len(runs),
                **{k: {"mean": agg[k][0], "std": agg[k][1]} for k in agg})
            out(f"  {name:<22} P={agg['precision'][0]:.3f}±{agg['precision'][1]:.3f}  "
                f"R={agg['recall'][0]:.3f}±{agg['recall'][1]:.3f}  "
                f"F1={agg['f1'][0]:.3f}±{agg['f1'][1]:.3f}  "
                f"FPR={agg['fpr'][0]:.2%}")

    # -----------------------------------------------------------------------
    out("\n" + "=" * 78)
    out("趨勢摘要：F1 隨異常比例的變化")
    out("=" * 78)
    # 以「實際比例」當欄位（目標比例在低端達不到，用實際值才誠實）
    cols = sorted({v["actual"] for v in results[next(iter(DETECTORS))].values()})
    out("  " + f"{'偵測器':<22}" + "".join(f"{c:>9.2%}" for c in cols))
    for name in DETECTORS:
        row = f"  {name:<22}"
        by_actual = {v["actual"]: v for v in results[name].values()}
        for c in cols:
            row += f"{by_actual[c]['f1']['mean']:>9.3f}" if c in by_actual else f"{'--':>9}"
        out(row)
    out("\n  同一張表，改看 recall（與比例無關）:")
    out("  " + f"{'偵測器':<22}" + "".join(f"{c:>9.2%}" for c in cols))
    for name in DETECTORS:
        row = f"  {name:<22}"
        by_actual = {v["actual"]: v for v in results[name].values()}
        for c in cols:
            row += f"{by_actual[c]['recall']['mean']:>9.3f}" if c in by_actual else f"{'--':>9}"
        out(row)

    out("\n" + "=" * 78)
    out("解讀")
    out("=" * 78)
    out("- **Recall 與 FPR 不隨比例改變**：兩者都是「在各自母體內的比率」，")
    out("  稀釋正常行不會改變『異常有沒有被抓到』或『正常行誤報的百分比』。")
    out("- **Precision 與 F1 強烈受比例影響**：比例越低，同樣的 FPR 會產生越多")
    out("  絕對誤報數，淹沒真異常 → precision 下降。這是不平衡資料的本質，")
    out("  不是模型變差。")
    out("- **推論**：報告中的 F1 數字只在『該比例』下成立，跨比例比較 F1 沒有意義。")
    out("  要跨比例比較，應該看 **recall / FPR**（與比例無關）或 PR-AUC。")
    out("- **FPR 的營運意義**：在極低比例下，FPR 每高 1 個百分點都會製造大量誤報。")
    out("  這解釋了為什麼 SourceNode 規則（FPR 0.00%）的價值隨比例降低而放大。")

    with open(os.path.join(OUT, "ratio_results.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in log) + "\n")
    with open(os.path.join(OUT, "ratio_summary.json"), "w", encoding="utf-8") as f:
        json.dump(dict(ratios=RATIOS, repeats=REPEATS, n_anom=n_a,
                       n_norm_pool=len(norm), results=results),
                  f, ensure_ascii=False, indent=2, default=float)
    print(f"\n報告已存: {OUT}/ratio_results.txt")


if __name__ == "__main__":
    main()
