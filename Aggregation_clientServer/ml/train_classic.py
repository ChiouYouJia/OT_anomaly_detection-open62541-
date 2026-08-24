#!/usr/bin/env python3
# =============================================================================
# train_classic.py ── 傳統 ML 異常檢測（無監督 IsolationForest + 監督 RandomForest）
# =============================================================================
# 輸入：ml/out/parsed_all.csv（由 parse_logs.py 產生）
# 目的：用第 1 層萃取的結構化/跨行特徵，做兩條對照線，並「分攻擊類別」評估
#       （因為 R 註定低 recall，混在一起會被稀釋看不出來）。
#
# 兩條線：
#   (A) 無監督 IsolationForest — 只喂特徵、不看標籤，模擬「真實情境沒有攻擊標籤」，
#       用 contamination≈實際異常比例。看它能不能無監督地把異常挑出來。
#   (B) 監督 RandomForest — 用標籤做 stratified 5-fold 交叉驗證，看特徵到底能不能
#       分開四種攻擊 + 各類別的 precision/recall/f1。
#
# 評估：極不平衡（~2% 異常），不用 accuracy。用 per-class precision/recall/f1、
#       混淆矩陣、PR-AUC。並特別檢視 R 的表現以佐證「R 最難自動偵測」。
#
# 執行：python3 ml/train_classic.py
# =============================================================================
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.metrics import (precision_recall_fscore_support, confusion_matrix,
                             classification_report, precision_recall_curve, auc)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")
df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"))

# ---- 特徵集 ----
# 數值/計數型跨行特徵（核心）：
NUM_FEATS = ["sensor_events_in_sec_persrc", "dist_ts_occurrence",
             "session_denied_cumcount", "is_write_denied"]
# 類別型：level_cat、role、template_id → one-hot（讓模型也能用「哪種模板/角色」）
#   ⚠ 用 role 而不是 source（2026-08-16 改）：source 在新格式下就是 SourceName，
#     三 pair 拓樸的取值是 Sensor/Sensor2/Sensor3/Motor/…，而 Sensor2/Sensor3/
#     Motor2/Motor3 **只存在於 topo3 批次** —— 這四個 one-hot 欄位等於「這一行來自
#     topo3 採集」的完美指標。本腳本是把 baseline/v2/topo3/densitysweep 混在一起
#     訓練的，讓特徵空間編碼採集批次身分沒有任何道理。
#     實測換成 role 後 P/R/F1 完全不變、PR-AUC 僅由 0.6245 → 0.6011，
#     確認 source 並未真的被模型利用；改掉是為了口徑乾淨，不是為了修正數字。
CAT_FEATS = ["level_cat", "role", "template_id"]

X_num = df[NUM_FEATS].fillna(0).astype(float)
X_cat = pd.get_dummies(df[CAT_FEATS].astype(str), prefix=CAT_FEATS)
X = pd.concat([X_num, X_cat], axis=1)
y = df["label"].astype(int).values
atype = df["attack_type"].values
groups = df["scenario"].values          # CV 分組鍵：整個場景一起 held-out

report = []
def out(s=""):
    print(s); report.append(str(s))

out("="*70)
out("資料概況")
out("="*70)
out(f"樣本數: {len(df)}   特徵維度: {X.shape[1]}")
out(f"異常(label=1): {int(y.sum())}   正常: {int((y==0).sum())}   異常比例: {y.mean():.3%}")
out(f"各攻擊類別: {dict(pd.Series(atype).value_counts())}")

# =============================================================================
# (A) 無監督 IsolationForest
# =============================================================================
out("\n" + "="*70)
out("(A) 無監督 IsolationForest（不看標籤，contamination=實際異常比例）")
out("="*70)
contam = max(y.mean(), 0.005)
iso = IsolationForest(n_estimators=300, contamination=contam, random_state=42)
iso_pred = iso.fit_predict(X_num.values)          # 只用數值特徵，避免 one-hot 稀釋
iso_pred = (iso_pred == -1).astype(int)           # -1=異常 -> 1
p, r, f, _ = precision_recall_fscore_support(y, iso_pred, average="binary", zero_division=0)
out(f"整體  precision={p:.3f}  recall={r:.3f}  f1={f:.3f}")
out("混淆矩陣 [列=真實(正常,異常), 欄=預測(正常,異常)]:")
out(confusion_matrix(y, iso_pred))
out("\n各攻擊類別被 IsolationForest 抓到的比例（recall by attack type）:")
for at in ["S", "T", "R", "RP"]:
    mask = atype == at
    if mask.sum() == 0: continue
    caught = iso_pred[mask].sum()
    out(f"  [{at}] 抓到 {caught}/{mask.sum()} = {caught/mask.sum():.0%}")

# =============================================================================
# (B) 監督 RandomForest（二分類：正常 vs 異常），**GroupKFold by scenario**
# =============================================================================
# ⚠ 切分改用 GroupKFold（2026-08-16 改）：原本的 StratifiedKFold(shuffle=True)
#   是逐「行」隨機分 fold，同一個場景的行會同時出現在 train 和 test。log 行在場景
#   內高度相關（同一批攻擊、同一段排程），這讓模型可以記住場景而不是學會行為。
#   改成整個場景一起 held-out 才是誠實的口徑。實測 PR-AUC 0.651 → 0.625。
out("\n" + "="*70)
out("(B) 監督 RandomForest 二分類（GroupKFold by scenario，5 折）")
out("="*70)
gkf = GroupKFold(n_splits=5)
rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42)
# 交叉驗證的 out-of-fold 預測（機率 + 標籤）
proba = cross_val_predict(rf, X.values, y, cv=gkf, groups=groups,
                          method="predict_proba")[:, 1]
pred  = (proba >= 0.5).astype(int)
p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
out(f"整體  precision={p:.3f}  recall={r:.3f}  f1={f:.3f}   （門檻 0.5）")
prec_c, rec_c, _ = precision_recall_curve(y, proba)
out(f"PR-AUC = {auc(rec_c, prec_c):.3f}   （與門檻無關；隨機基準 = {y.mean():.4f}）")
out("混淆矩陣 [列=真實, 欄=預測]:")
out(confusion_matrix(y, pred))

# ---- ⚠ 逐類別 recall 必須連同當下的 precision 一起看 ----
#   class_weight="balanced" 在 ~0.5% 的基礎率上把正類權重放大約 200 倍，
#   門檻 0.5 於是幾乎失去意義：模型把大片正常行也標成異常，才換到漂亮的 recall。
#   單獨引用「[R] 100%」會嚴重誤導 —— 所以這裡把 precision 印在同一行。
out(f"\n各攻擊類別 recall（⚠ 此操作點的整體 precision 僅 {p:.3f}，"
    f"誤報 {int(((pred==1)&(y==0)).sum())} 行）:")
for at in ["S", "T", "R", "RP"]:
    mask = atype == at
    if mask.sum() == 0: continue
    caught = pred[mask].sum()
    out(f"  [{at}] 抓到 {caught}/{mask.sum()} = {caught/mask.sum():.0%}")

# ---- 另補一個「可用」的操作點：把門檻抬到整體 precision >= 0.5 ----
#   讓報告同時有「模型排序能力」與「真的要用時長什麼樣」兩個面向。
cand = [t for t in np.unique(np.round(proba, 3))
        if ((proba >= t) & (y == 1)).sum() and
           ((proba >= t) & (y == 1)).sum() / max(((proba >= t).sum()), 1) >= 0.5]
if cand:
    t50 = min(cand)
    pr2 = (proba >= t50).astype(int)
    p2, r2, f2, _ = precision_recall_fscore_support(y, pr2, average="binary", zero_division=0)
    out(f"\n改用 precision>=0.5 的操作點（門檻 {t50:.3f}）:")
    out(f"  整體  precision={p2:.3f}  recall={r2:.3f}  f1={f2:.3f}  "
        f"誤報 {int(((pr2==1)&(y==0)).sum())} 行")
    for at in ["S", "T", "R", "RP"]:
        mask = atype == at
        if mask.sum() == 0: continue
        out(f"  [{at}] 抓到 {int(pr2[mask].sum())}/{mask.sum()} = {pr2[mask].mean():.0%}")
else:
    out("\n找不到 precision>=0.5 的操作點 —— 這個特徵集在本資料上無法產生可用的偵測器。")

# 特徵重要度（在全資料 refit 一次取 importance）
rf.fit(X.values, y)
imp = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)
out("\n特徵重要度 Top 10:")
out(imp.head(10).to_string())

# =============================================================================
# 結論
# =============================================================================
out("\n" + "="*70)
out("結論")
out("="*70)
out("- S/T/RP 各有乾淨可分的跨行計數特徵（persrc 每秒雙報 / denied 累計 / dtso 重複），")
out("  監督模型在這三類上確實有高 recall。特徵重要度也由這些欄位主導。")
out("- ⚠ 但門檻 0.5 的 recall 不可單獨引用：class_weight='balanced' 在 ~0.5% 的")
out("  基礎率上把正類權重放大約 200 倍，模型是用大量誤報換到那個 recall 的。")
out("  要看『真的能不能用』請引用上面 precision>=0.5 的操作點，或直接看 PR-AUC。")
out("- R 的處理：本腳本**沒有**套用 eval_v2.py / ablation_leakage.py / hybrid_detector.py")
out("  所做的洩漏補正（攻擊專屬模板併入正常 + dtso 補正）。R 偽造的 motor 行帶著")
out("  正常訓練集不存在的模板，模型可以純靠模板記憶抓到 —— 那不是行為偵測能力。")
out("  要引用 R 的數字請改看那三支腳本。")
out("- 切分：GroupKFold by scenario，整個場景一起 held-out。舊版用逐行隨機的")
out("  StratifiedKFold，同場景的行會同時進 train/test，PR-AUC 會虛高約 0.03。")
out("- 拓樸更新（2026-08-16）：三 pair 資料下 R 已有 330 筆、RP 204 筆，")
out("  不再是舊單 pair 時代的『R=4，僅案例級佐證』。樣本數已足夠做統計陳述。")

open(os.path.join(OUT, "classic_results.txt"), "w", encoding="utf-8").write(
    "\n".join(str(x) for x in report) + "\n")
print(f"\n報告已存: {OUT}/classic_results.txt")
