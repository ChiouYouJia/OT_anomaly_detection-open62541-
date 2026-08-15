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
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (precision_recall_fscore_support, confusion_matrix,
                             classification_report, precision_recall_curve, auc)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")
df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"))

# ---- 特徵集 ----
# 數值/計數型跨行特徵（核心）：
NUM_FEATS = ["sensor_events_in_sec", "dist_ts_occurrence",
             "session_denied_cumcount", "is_write_denied"]
# 類別型：level_cat、source、template_id → one-hot（讓模型也能用「哪種模板/來源」）
CAT_FEATS = ["level_cat", "source", "template_id"]

X_num = df[NUM_FEATS].fillna(0).astype(float)
X_cat = pd.get_dummies(df[CAT_FEATS].astype(str), prefix=CAT_FEATS)
X = pd.concat([X_num, X_cat], axis=1)
y = df["label"].astype(int).values
atype = df["attack_type"].values

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
# (B) 監督 RandomForest（二分類：正常 vs 異常），stratified 5-fold CV
# =============================================================================
out("\n" + "="*70)
out("(B) 監督 RandomForest 二分類（stratified 5-fold 交叉驗證）")
out("="*70)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42)
# 交叉驗證的 out-of-fold 預測（機率 + 標籤）
proba = cross_val_predict(rf, X.values, y, cv=skf, method="predict_proba")[:, 1]
pred  = (proba >= 0.5).astype(int)
p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
out(f"整體  precision={p:.3f}  recall={r:.3f}  f1={f:.3f}")
prec_c, rec_c, _ = precision_recall_curve(y, proba)
out(f"PR-AUC = {auc(rec_c, prec_c):.3f}")
out("混淆矩陣 [列=真實, 欄=預測]:")
out(confusion_matrix(y, pred))
out("\n各攻擊類別被 RandomForest 抓到的比例（recall by attack type）:")
for at in ["S", "T", "R", "RP"]:
    mask = atype == at
    if mask.sum() == 0: continue
    caught = pred[mask].sum()
    out(f"  [{at}] 抓到 {caught}/{mask.sum()} = {caught/mask.sum():.0%}")

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
out("- S/T/RP 各有乾淨可分的跨行計數特徵，監督模型應可高 recall 抓到。")
out("- R 在所有行為特徵上與正常一致（見特徵 max 全為 0/1），模型註定漏抓 →")
out("  這在數據上佐證『否認攻擊的破綻是缺乏來源歸屬，非行為/內容異常』。")
out("- 注意：R/RP 樣本極少（R=4），此結果為案例級佐證，非統計顯著；")
out("  要嚴謹評估需大量產生正常 baseline + 更多 R 樣本。")

open(os.path.join(OUT, "classic_results.txt"), "w", encoding="utf-8").write(
    "\n".join(str(x) for x in report) + "\n")
print(f"\n報告已存: {OUT}/classic_results.txt")
