#!/usr/bin/env python3
# =============================================================================
# deeplog.py ── 第 2 層：DeepLog (LSTM) 序列異常檢測
# =============================================================================
# 原理（DeepLog, Du et al. CCS'17 的核心）：
#   把 log 轉成「模板 ID 序列」，用 LSTM 學「給定前 h 個模板，正常情況下一個模板
#   是哪個」。訓練『只用正常資料』。偵測時：若實際出現的模板不在模型預測的 top-k
#   候選內 → 該位置判為異常。專治「序列/時序異常」（正常模板順序被打亂）。
#
# 對應本專案的攻擊：
#   - S 欺騙：在正常「每秒一筆 sensor」序列裡插入額外 sensor 事件 → 打亂序列
#   - R 否認：插入正常序列中不該出現的 motor 模板 → 序列違例
#   - T/RP：也可能造成 session/模板序列的異常轉移
#
# 資料切分（關鍵：訓練只用正常）：
#   train = 純正常 baseline 場景（baseline_*）
#   test  = 有攻擊的場景（其餘），用 parsed_all.csv 的 label 評估
#
# 執行： ml/venv/bin/python ml/deeplog.py
# 輸出： ml/out/deeplog_results.txt
# =============================================================================
import os, sys
import numpy as np
import pandas as pd

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")
torch.manual_seed(42); np.random.seed(42)

# ---- 超參數 ----
WINDOW   = 10      # 用前 10 個模板預測下一個
HIDDEN   = 64
LAYERS   = 2
EPOCHS   = 15
BATCH    = 128
TOPK     = 3       # 實際模板不在預測 top-k 內 → 異常
LR       = 1e-3

def load():
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    # 場景過濾（與 ngram_detector.py 同口徑）：SCENARIO_FILTER 子字串比對，
    # 只留某一批資料。例：SCENARIO_FILTER=20260811 ml/venv/bin/python ml/deeplog.py
    filt = os.environ.get("SCENARIO_FILTER", "").strip()
    if filt:
        df = df[df["scenario"].str.contains(filt, regex=False)].copy()
    # 模板 ID 轉整數索引（用過濾後資料建字典，確保 train/test 一致）
    tmpl_vocab = {t: i for i, t in enumerate(sorted(df["template_id"].astype(str).unique()))}
    df["tid"] = df["template_id"].astype(str).map(tmpl_vocab)
    return df, tmpl_vocab

def make_windows(seq, labels=None):
    """從一個場景的模板序列切滑動視窗。回傳 (X, y_next, idx_of_next)。"""
    X, ynext, idx = [], [], []
    for i in range(len(seq) - WINDOW):
        X.append(seq[i:i+WINDOW])
        ynext.append(seq[i+WINDOW])
        idx.append(i+WINDOW)
    return np.array(X), np.array(ynext), np.array(idx)

class DeepLog(nn.Module):
    def __init__(self, vocab, hidden, layers):
        super().__init__()
        self.emb = nn.Embedding(vocab, hidden)
        self.lstm = nn.LSTM(hidden, hidden, layers, batch_first=True)
        self.fc = nn.Linear(hidden, vocab)
    def forward(self, x):
        x = self.emb(x)
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])     # 用最後一步預測下一個模板

def main():
    df, vocab = load()
    V = len(vocab)
    log = []
    def out(s=""):
        print(s); log.append(str(s))

    out("="*68)
    out("DeepLog (LSTM) 序列異常檢測")
    out("="*68)
    out(f"模板詞彙量 V={V}  window={WINDOW}  top-k={TOPK}  hidden={HIDDEN}  layers={LAYERS}")

    # ---- 切分：train=純正常 baseline，test=有攻擊的場景 ----
    # ⚠ 切分用『包含 baseline』而非 startswith("baseline")：
    #   v2_baseline_60min / v2_baseline_ctrl_* 都是 "v2_" 開頭，用 startswith 會被
    #   誤丟進測試集 —— 少了訓練資料、測試集又被灌入純正常行（TN 虛高、FPR 稀釋）。
    #   與 ngram_detector.py / compare_ngram_deeplog.py 的切分口徑對齊。
    scen = df["scenario"].unique()
    train_scen = [s for s in scen if "baseline" in s]
    test_scen  = [s for s in scen if "baseline" not in s]
    if not train_scen:
        out("沒有 baseline_ 場景可當訓練集，請先跑 collect_baseline.sh");
        open(os.path.join(OUT,"deeplog_results.txt"),"w").write("\n".join(log)); return
    out(f"訓練場景(純正常): {train_scen}")
    out(f"測試場景(含攻擊): {test_scen}")

    # 訓練視窗（只用正常序列）
    Xtr, ytr = [], []
    for s in train_scen:
        seq = df[df.scenario==s].sort_values("seq_pos")["tid"].values
        X, y, _ = make_windows(seq)
        if len(X): Xtr.append(X); ytr.append(y)
    Xtr = np.concatenate(Xtr); ytr = np.concatenate(ytr)
    out(f"訓練視窗數: {len(Xtr)}")

    # ---- 訓練 ----
    dev = "cpu"
    model = DeepLog(V, HIDDEN, LAYERS).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    lossf = nn.CrossEntropyLoss()
    ds = TensorDataset(torch.tensor(Xtr, dtype=torch.long), torch.tensor(ytr, dtype=torch.long))
    dl = DataLoader(ds, batch_size=BATCH, shuffle=True)
    model.train()
    for ep in range(EPOCHS):
        tot = 0.0
        for xb, yb in dl:
            opt.zero_grad()
            out_logits = model(xb)
            loss = lossf(out_logits, yb)
            loss.backward(); opt.step()
            tot += loss.item()*len(xb)
        out(f"  epoch {ep+1:2d}/{EPOCHS}  loss={tot/len(ds):.4f}")

    # ---- 評估：對每個測試場景，逐視窗判斷 top-k 是否命中 ----
    out("\n" + "-"*68)
    out("評估（實際模板不在預測 top-k → 該行判為異常）")
    out("-"*68)
    model.eval()
    # 收集所有測試視窗的 (是否異常預測, 真實label, 攻擊類別)
    all_pred, all_true, all_type = [], [], []
    with torch.no_grad():
        for s in test_scen:
            sub = df[df.scenario==s].sort_values("seq_pos").reset_index(drop=True)
            seq = sub["tid"].values
            X, ynext, idxs = make_windows(seq)
            if len(X)==0: continue
            logits = model(torch.tensor(X, dtype=torch.long))
            topk = torch.topk(logits, TOPK, dim=1).indices.numpy()  # (N, k)
            miss = np.array([ynext[i] not in topk[i] for i in range(len(ynext))])
            # 對映回原始行的 label / attack_type（預測的是 idx 位置那一行）
            lab = sub.loc[idxs, "label"].values
            typ = sub.loc[idxs, "attack_type"].values
            all_pred.append(miss.astype(int)); all_true.append(lab); all_type.append(typ)
    pred = np.concatenate(all_pred); true = np.concatenate(all_true); typ = np.concatenate(all_type)

    from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
    p,r,f,_ = precision_recall_fscore_support(true, pred, average="binary", zero_division=0)
    out(f"整體  precision={p:.3f}  recall={r:.3f}  f1={f:.3f}")
    out("混淆矩陣 [列=真實(正常,異常), 欄=預測]:")
    out(confusion_matrix(true, pred))
    out("\n各攻擊類別被 DeepLog 抓到的比例（recall by attack type）:")
    for at in ["S","T","R","RP"]:
        m = typ==at
        if m.sum()==0: continue
        caught = pred[m].sum()
        out(f"  [{at}] 抓到 {caught}/{m.sum()} = {caught/m.sum():.0%}")

    # 誤報率（正常被判異常）
    normal_mask = true==0
    fpr = pred[normal_mask].sum()/max(normal_mask.sum(),1)
    out(f"\n正常誤報率 (FPR) = {pred[normal_mask].sum()}/{normal_mask.sum()} = {fpr:.2%}")

    out("\n" + "="*68)
    out("解讀")
    out("="*68)
    out("- DeepLog 只用正常序列訓練，靠『下一個模板是否在預測 top-k』判異常。")
    out("- 它對付『序列被打亂』型攻擊；S/R 插入了正常序列不預期的模板應被抓到。")
    out("- 若 R 這裡也被抓到，是因為 R 的模板在正常訓練資料從未出現 → 與傳統 ML 的")
    out("  『洩漏』本質相同（本機無 GPIO，真 motor 不產生 too close/safe 模板）。")
    out("  在有 GPIO 環境，R 模板會出現在正常訓練集，DeepLog 對 R 也會失效。")
    out("- FPR 是關鍵：DeepLog 常見問題是誤報高（正常但罕見的模板轉移被誤判）。")

    open(os.path.join(OUT,"deeplog_results.txt"),"w",encoding="utf-8").write("\n".join(str(x) for x in log)+"\n")
    print(f"\n報告已存: {OUT}/deeplog_results.txt")

if __name__ == "__main__":
    main()
