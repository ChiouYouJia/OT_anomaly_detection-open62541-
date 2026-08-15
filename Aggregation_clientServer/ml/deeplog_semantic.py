#!/usr/bin/env python3
# =============================================================================
# deeplog_semantic.py ── 第3層(任務2)：語意向量 DeepLog（vs 整數 embedding）
# =============================================================================
# 想法：把 DeepLog 的 nn.Embedding(整數 template_id) 換成『凍結的 sentence-
#   transformer 語意向量』。差別：
#     - 原版：template_id 是隨機初始化、訓練學出來的向量，語意上「T5 vs T8」無關聯。
#     - 本版：模板向量來自預訓練語意空間，語意相近的模板向量本就相近 →
#       期望對『罕見但語意正常』的模板轉移更寬容 → 降低 FPR。
#
# 兩者用『完全相同』的資料切分/超參/評估，只換輸入表示，公平對照。
# 需先跑 embed_semantic.py 產生 template_embeddings.npy。
#
# 執行： ml/venv/bin/python ml/deeplog_semantic.py
# 輸出： ml/out/deeplog_semantic_results.txt
# =============================================================================
import os
import numpy as np
import pandas as pd
import torch, torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")
torch.manual_seed(42); np.random.seed(42)

WINDOW, HIDDEN, LAYERS, EPOCHS, BATCH, TOPK, LR = 10, 64, 2, 15, 128, 3, 1e-3

def make_windows(seq):
    X, ynext, idx = [], [], []
    for i in range(len(seq) - WINDOW):
        X.append(seq[i:i+WINDOW]); ynext.append(seq[i+WINDOW]); idx.append(i+WINDOW)
    return np.array(X), np.array(ynext), np.array(idx)

class SemDeepLog(nn.Module):
    """輸入是 template_id 整數，但 embedding 用『凍結的語意向量』查表。"""
    def __init__(self, sem_matrix, hidden, layers, vocab):
        super().__init__()
        # 凍結的語意 embedding（384維）→ 投影到 hidden
        self.emb = nn.Embedding.from_pretrained(torch.tensor(sem_matrix, dtype=torch.float32),
                                                freeze=True)
        self.proj = nn.Linear(sem_matrix.shape[1], hidden)
        self.lstm = nn.LSTM(hidden, hidden, layers, batch_first=True)
        self.fc = nn.Linear(hidden, vocab)     # 仍預測 vocab 個模板中的哪一個
    def forward(self, x):
        e = self.proj(self.emb(x))
        out, _ = self.lstm(e)
        return self.fc(out[:, -1, :])

def main():
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"))
    sem = np.load(os.path.join(OUT, "template_embeddings.npy"))  # (V,384)，順序=sorted template_id
    log = []
    def out(s=""):
        print(s); log.append(str(s))

    # template_id -> 索引（與 embed_semantic.py 一致：sorted）
    tids = sorted(df["template_id"].unique())
    vocab = {t: i for i, t in enumerate(tids)}
    df["tid"] = df["template_id"].map(vocab)
    V = len(vocab)

    out("="*68)
    out("語意向量 DeepLog（凍結 all-MiniLM 384維 embedding）")
    out("="*68)
    out(f"V={V}  window={WINDOW}  top-k={TOPK}  (與整數版 deeplog.py 相同超參)")

    train_scen = [s for s in df.scenario.unique() if s.startswith("baseline")]
    test_scen  = [s for s in df.scenario.unique() if not s.startswith("baseline")]

    Xtr, ytr = [], []
    for s in train_scen:
        seq = df[df.scenario==s].sort_values("seq_pos")["tid"].values
        X, y, _ = make_windows(seq)
        if len(X): Xtr.append(X); ytr.append(y)
    Xtr = np.concatenate(Xtr); ytr = np.concatenate(ytr)

    model = SemDeepLog(sem, HIDDEN, LAYERS, V)
    opt = torch.optim.Adam(filter(lambda p: p.requires_grad, model.parameters()), lr=LR)
    lossf = nn.CrossEntropyLoss()
    dl = DataLoader(TensorDataset(torch.tensor(Xtr), torch.tensor(ytr)),
                    batch_size=BATCH, shuffle=True)
    model.train()
    for ep in range(EPOCHS):
        tot=0.0
        for xb,yb in dl:
            opt.zero_grad(); loss=lossf(model(xb), yb); loss.backward(); opt.step()
            tot+=loss.item()*len(xb)
        if (ep+1)%5==0: out(f"  epoch {ep+1:2d}/{EPOCHS}  loss={tot/len(Xtr):.4f}")

    model.eval()
    ap,at_,att=[],[],[]
    with torch.no_grad():
        for s in test_scen:
            sub=df[df.scenario==s].sort_values("seq_pos").reset_index(drop=True)
            seq=sub["tid"].values
            X,ynext,idxs=make_windows(seq)
            if len(X)==0: continue
            logits=model(torch.tensor(X))
            topk=torch.topk(logits,TOPK,dim=1).indices.numpy()
            miss=np.array([ynext[i] not in topk[i] for i in range(len(ynext))])
            ap.append(miss.astype(int)); at_.append(sub.loc[idxs,"label"].values)
            att.append(sub.loc[idxs,"attack_type"].values)
    pred=np.concatenate(ap); true=np.concatenate(at_); typ=np.concatenate(att)

    p,r,f,_=precision_recall_fscore_support(true,pred,average="binary",zero_division=0)
    out(f"\n整體  precision={p:.3f}  recall={r:.3f}  f1={f:.3f}")
    out("混淆矩陣 [列=真實, 欄=預測]:"); out(confusion_matrix(true,pred))
    out("\n各攻擊類別 recall:")
    for a in ["S","T","R","RP"]:
        m=typ==a
        if m.sum()==0: continue
        out(f"  [{a}] {pred[m].sum()}/{m.sum()} = {pred[m].sum()/m.sum():.0%}")
    nm=true==0
    out(f"\n正常誤報率 (FPR) = {pred[nm].sum()}/{nm.sum()} = {pred[nm].sum()/nm.sum():.2%}")
    out("\n（與整數版 deeplog.py 的 FPR 對比，即可看語意向量有沒有降誤報）")

    open(os.path.join(OUT,"deeplog_semantic_results.txt"),"w",encoding="utf-8").write(
        "\n".join(str(x) for x in log)+"\n")
    print(f"\n報告已存: {OUT}/deeplog_semantic_results.txt")

if __name__=="__main__":
    main()
