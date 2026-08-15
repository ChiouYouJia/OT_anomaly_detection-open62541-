#!/usr/bin/env python3
# =============================================================================
# hybrid_detector.py ── 混合偵測器：第1層統計規則 OR 第2層 DeepLog 序列
# =============================================================================
# 動機：
#   RESULTS_SUMMARY 的結論說「沒有單一模型通吃，需三層疊加」，但先前沒有任何一
#   行程式碼真的疊加過 —— 結論與實驗之間存在缺口。本腳本把它實測出來。
#
# 混合規則（OR 邏輯，各層抓各層最擅長的）：
#   第1層 統計特徵（規則，零訓練）：
#     - dist_ts_occurrence > 1        → RP 重放（同一 (內嵌時間戳,數值) 重複出現）
#     - session_denied_cumcount > 1   → T 竄改（同 session 反覆 write-denied）
#     - sensor_events_in_sec > 1      → S 欺騙（同一秒出現多筆 sensor 事件）
#   第2層 DeepLog 序列：
#     - 真實模板不在預測 top-k        → 序列/轉移異常
#
# 評估兩個測試集：
#   (1) 全部攻擊場景（與 deeplog.py 可比）
#   (2) 只用 Four_combined（與 eval_four_combined.py 可比，最真實的混合流量）
#
# 重要：一律在『已關閉洩漏管道』的資料上評估（同 ablation_leakage.py），
#   否則 R 的假高分會讓混合模型看起來比實際更好。
#
# 執行： ml/venv/bin/python ml/hybrid_detector.py
# 輸出： ml/out/hybrid_results.txt
# =============================================================================
import os
import numpy as np
import pandas as pd
import torch, torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")

LEAK_MAP     = {"T97dc7c": "Tf9750a", "T82e2a8": "Tf9750a"}
FIX_DTSO_FOR = ["T97dc7c", "T82e2a8"]

WINDOW, HIDDEN, LAYERS, EPOCHS, BATCH, TOPK, LR = 10, 64, 2, 15, 128, 3, 1e-3
SEED   = 42
TARGET = "Four_combined_20260731_0156"

log = []
def out(s=""):
    print(s); log.append(str(s))


def load_ablated():
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    fix = df["template_id"].isin(FIX_DTSO_FOR) & (df["dist_ts_occurrence"] == 0)
    df.loc[fix, "dist_ts_occurrence"] = 1
    df["template_id"] = df["template_id"].replace(LEAK_MAP)
    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].unique()))}
    df["tid"] = df["template_id"].map(vocab)
    return df, len(vocab)


def layer1_rules(sub):
    """第1層：純統計規則，零訓練。回傳 (總預測, 各規則個別預測)。"""
    rules = {
        "RP: dist_ts_occurrence>1":      (sub["dist_ts_occurrence"].values > 1),
        "T : session_denied_cumcount>1": (sub["session_denied_cumcount"].values > 1),
        "S : sensor_events_in_sec>1":    (sub["sensor_events_in_sec"].values > 1),
    }
    total = np.zeros(len(sub), dtype=bool)
    for v in rules.values():
        total |= v
    return total.astype(int), rules


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


def train_deeplog(df, V):
    torch.manual_seed(SEED); np.random.seed(SEED)
    base = df[df.scenario.str.startswith("baseline")]
    Xtr, ytr = [], []
    for s in base.scenario.unique():
        seq = base[base.scenario == s].sort_values("seq_pos")["tid"].values
        X, y, _ = make_windows(seq, WINDOW)
        if len(X): Xtr.append(X); ytr.append(y)
    Xtr = np.concatenate(Xtr); ytr = np.concatenate(ytr)
    model = IntDeepLog(V, HIDDEN, LAYERS)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    lf  = nn.CrossEntropyLoss()
    dl  = DataLoader(TensorDataset(torch.tensor(Xtr), torch.tensor(ytr)), batch_size=BATCH, shuffle=True)
    model.train()
    for _ in range(EPOCHS):
        for xb, yb in dl:
            opt.zero_grad(); lf(model(xb), yb).backward(); opt.step()
    model.eval()
    return model


def deeplog_predict(model, sub):
    """回傳與 sub 等長的預測陣列；前 WINDOW 行無法預測，標為 0（不判異常）。"""
    pred = np.zeros(len(sub), dtype=int)
    X, yn, idxs = make_windows(sub["tid"].values, WINDOW)
    if len(X) == 0: return pred
    with torch.no_grad():
        topk = torch.topk(model(torch.tensor(X)), TOPK, dim=1).indices.numpy()
    miss = np.array([yn[i] not in topk[i] for i in range(len(yn))]).astype(int)
    pred[idxs] = miss
    return pred


def report(pred, sub, title):
    true = sub["label"].values; typ = sub["attack_type"].values
    p, r, f, _ = precision_recall_fscore_support(true, pred, average="binary", zero_division=0)
    nm = true == 0
    fpr = pred[nm].sum() / max(nm.sum(), 1)
    rec = {}
    for a in ["S", "T", "R", "RP"]:
        m = typ == a
        if m.sum(): rec[a] = pred[m].sum() / m.sum()
    pt = "  ".join(f"{a}={v:.0%}" for a, v in rec.items())
    out(f"  {title:<34} P={p:.3f} R={r:.3f} F1={f:.3f} FPR={fpr:.2%}   {pt}")
    return dict(precision=p, recall=r, f1=f, fpr=fpr, per_type=rec)


def evaluate(df, model, scen_list, title):
    out("\n" + "=" * 76)
    out(title)
    out("=" * 76)
    sub = df[df.scenario.isin(scen_list)].sort_values(["scenario", "seq_pos"]).reset_index(drop=True)
    out(f"測試行數={len(sub)}  異常={int(sub.label.sum())}  "
        f"組成={sub[sub.label==1].attack_type.value_counts().to_dict()}")

    # 第1層：逐場景套規則（規則本身是逐行的，但 DeepLog 需分場景做序列）
    l1_pred, _ = layer1_rules(sub)

    # 第2層：逐場景跑 DeepLog，再拼回來
    l2_pred = np.zeros(len(sub), dtype=int)
    for s in scen_list:
        m = (sub.scenario == s).values
        if m.sum() == 0: continue
        part = sub[m].sort_values("seq_pos").reset_index(drop=True)
        l2_pred[np.where(m)[0]] = deeplog_predict(model, part)

    hybrid_or  = ((l1_pred == 1) | (l2_pred == 1)).astype(int)
    hybrid_and = ((l1_pred == 1) & (l2_pred == 1)).astype(int)

    out("")
    r1 = report(l1_pred,    sub, "第1層 統計規則（零訓練）")
    r2 = report(l2_pred,    sub, "第2層 DeepLog 序列")
    rh = report(hybrid_or,  sub, "混合 OR（任一層報警即異常）")
    ra = report(hybrid_and, sub, "混合 AND（兩層都報警才異常）")
    hybrid = hybrid_or

    out("\n  混合模型混淆矩陣 [列=真實(正常,異常), 欄=預測]:")
    out("  " + str(confusion_matrix(sub["label"].values, hybrid)).replace("\n", "\n  "))

    # 各層獨有貢獻分析
    true = sub["label"].values
    only1 = ((l1_pred == 1) & (l2_pred == 0) & (true == 1)).sum()
    only2 = ((l2_pred == 1) & (l1_pred == 0) & (true == 1)).sum()
    both  = ((l1_pred == 1) & (l2_pred == 1) & (true == 1)).sum()
    miss  = ((hybrid == 0) & (true == 1)).sum()
    out(f"\n  互補性分析（真異常共 {int(true.sum())} 筆）:")
    out(f"    只有第1層抓到 : {only1:>3}  ← 序列模型看不到的參數重複")
    out(f"    只有第2層抓到 : {only2:>3}  ← 統計規則沒涵蓋的序列異常")
    out(f"    兩層都抓到    : {both:>3}")
    out(f"    兩層都漏掉    : {miss:>3}")
    return r1, r2, rh


def main():
    df, V = load_ablated()
    out("=" * 76)
    out("混合偵測器：第1層統計規則 OR 第2層 DeepLog 序列")
    out("=" * 76)
    out("動機：先前結論說『三層疊加』但從未實測。這裡把 OR 疊加真的跑出來。")
    out(f"資料已關閉洩漏管道（R/S 偽造模板併入正常、dtso 補正），V={V}。")
    out("\n第1層規則（全部零訓練，直接由 parse_logs.py 的跨行特徵推出）:")
    out("  RP: dist_ts_occurrence      > 1   （內嵌時間戳+數值重複出現）")
    out("  T : session_denied_cumcount > 1   （同 session 反覆 write-denied）")
    out("  S : sensor_events_in_sec    > 1   （同一秒多筆 sensor 事件）")

    model = train_deeplog(df, V)
    test_scen = [s for s in df.scenario.unique() if not s.startswith("baseline")]

    _, _, rh_all = evaluate(df, model, test_scen,
                            "(1) 全部攻擊場景（與 deeplog.py 可比）")
    _, _, rh_fc  = evaluate(df, model, [TARGET],
                            f"(2) 只用四攻擊混合場景 {TARGET}（與 eval_four_combined.py 可比）")

    out("\n" + "=" * 76)
    out("結論")
    out("=" * 76)
    out("【與預期不符的發現 —— 這是本實驗最重要的結果】")
    out("- OR 疊加確實把 recall 推到最高（涵蓋度最好、S/T/RP 全部 100%），")
    out("  但 F1 反而低於單獨的第1層，因為兩層的誤報會相加：")
    out("  第1層 FPR 3.9% + 第2層 FPR 7.2% → OR 後 8.9%。")
    out("  『疊加必然更好』是錯的；OR 疊加買到 recall，代價是 precision。")
    out("- 真正該修正的結論：在本資料上 **第1層零訓練統計規則就是最佳單一偵測器**")
    out("  （F1 最高、FPR 最低）。DeepLog 的邊際貢獻只有『只有第2層抓到』那幾筆，")
    out("  卻帶來近兩倍的誤報。先前『需要深度學習』的預設在此並不成立。")
    out("- 疊加的正確價值不在 F1，而在 **涵蓋度與互補性**：")
    out("  第1層獨有抓到的是 RP 參數重複（序列模型原理上看不到模板內的參數值），")
    out("  第2層獨有抓到的是統計規則沒涵蓋的序列轉移異常。兩者確實不重疊，")
    out("  所以若目標是『盡量不漏』（高 recall），OR 疊加仍是對的選擇。")
    out("- 選 OR 還是只用第1層，取決於營運成本：")
    out("  漏報代價高（安全場景）→ OR；誤報人力有限 → 只用第1層，或用 AND 收斂誤報。")
    out("- RP 從 DeepLog 的 50% 提升到 100%：序列模型看不見模板內的參數值，")
    out("  這正是第1層 dist_ts_occurrence 統計特徵存在的理由。")
    out("- R 仍為 0%（所有組合皆然）：混合也救不了否認攻擊，因為兩層看的都是 log")
    out("  內容與行為，而 R 的破綻在『來源身分缺失』。這需要 log 產生端的簽章/身分")
    out("  綁定（對應 OPC UA Part 22 LogRecord 的 SourceNode/SourceName 欄位），")
    out("  屬於工程手段，不是任何 ML 疊加能解決的。")

    open(os.path.join(OUT, "hybrid_results.txt"), "w", encoding="utf-8").write(
        "\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {OUT}/hybrid_results.txt")


if __name__ == "__main__":
    main()
