#!/usr/bin/env python3
# =============================================================================
# check_spoof_tier.py ── 驗證兩階欺騙威脅模型之難度差異存在於「值」維度
# =============================================================================
# 動機：mvdeeplog 合併分數之逐行 ROC 顯示 Sphys(0.998) > Snaive(0.911)，與「物理
#   感知較難抓」之直覺矛盾。本腳本以**模型無關**之單步 |Δ| 檢定證實：難度差異
#   確實存在，但僅在**值維度**；合併分數被時序(dt)頭主宰而掩蓋了此差異。
#
# 單步 |Δ| = |注入/讀數值 − 同 SourceName 前一筆值|
#   · Snaive：注入均勻亂數 → |Δ| 大 → 易分
#   · Sphys ：注入當前值 ±0.75 → |Δ| 小（甚至小於正常步長）→ 值檢定失效
#
# 執行：ml/venv/bin/python ml/check_spoof_tier.py   → 印表；另見 out/mvdeeplog_results_S*.txt
#   之逐分量診斷(val 分量 ROC：Snaive 0.928 vs Sphys 0.426)。
# =============================================================================
import os
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
df = pd.read_csv(os.path.join(HERE, "out", "parsed_all.csv"), low_memory=False)
df = df[df.scenario.str.contains("topo3", na=False)].copy()
df = df.sort_values(["scenario", "seq_pos"]).reset_index(drop=True)


def step_auc(sub):
    s = sub[(sub.role == "Sensor") & sub.dist.notna()].copy()
    s["prev"] = s.groupby("lr_SourceName")["dist"].shift(1)
    s = s.dropna(subset=["prev"])
    s["absdelta"] = (s.dist - s.prev).abs()
    y = (s.attack_type == "S").astype(int).values
    if y.sum() == 0 or (y == 0).sum() == 0:
        return None
    return (roc_auc_score(y, s["absdelta"].values), int(y.sum()),
            float(np.median(s.absdelta[y == 1])), float(np.median(s.absdelta[y == 0])))


print(f"{'場景':<8}{'單步|Δ| ROC':>13}{'S |Δ|中位':>12}{'benign |Δ|中位':>16}{'S 數':>7}")
for tag in ["Snaive", "Sphys"]:
    r = step_auc(df[df.scenario.str.contains(tag)])
    if r:
        auc, n, md_s, md_b = r
        print(f"{tag:<8}{auc:>13.3f}{md_s:>12.3f}{md_b:>16.3f}{n:>7}")
print("\n判讀：naive 單步 |Δ| 遠大於正常→易分；phys |Δ| 甚至小於正常→值檢定失效。")
print("對照 mvdeeplog 逐分量：val 分量 ROC Snaive 0.928 vs Sphys 0.426（同結論）；")
print("      dt 分量 ROC Snaive 0.938 vs Sphys 0.998（時序主宰合併分數，掩蓋值維度差異）。")
