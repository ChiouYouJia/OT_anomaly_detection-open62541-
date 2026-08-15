#!/usr/bin/env python3
# =============================================================================
# eval_four_combined.py ── 專門在「四攻擊混合」場景上評估三個模型
# =============================================================================
# 動機：先前評估把所有測試場景混在一起算總分，Four_combined（唯一同時含
#   S+T+R+RP 的最真實場景）的表現被單一攻擊場景平均掉了。這裡『只用
#   Four_combined 當測試集』單獨評估，看模型在四攻擊並存的真實流量下的實際表現。
#
# 三個模型都只用『純正常 baseline』訓練/擬合，Four_combined 完全沒參與訓練，
# 所以拿它當獨立測試集完全合法。
#
# 執行： ml/venv/bin/python ml/eval_four_combined.py
# 輸出： ml/out/four_combined_eval.txt
# =============================================================================
import os
import numpy as np
import pandas as pd
import torch, torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")
torch.manual_seed(42); np.random.seed(42)

TARGET = "Four_combined_20260731_0156"
WINDOW, HIDDEN, LAYERS, EPOCHS, BATCH, TOPK, LR = 10, 64, 2, 15, 128, 3, 1e-3

df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"))
tids = sorted(df["template_id"].unique())
vocab = {t: i for i, t in enumerate(tids)}
df["tid"] = df["template_id"].map(vocab)
V = len(vocab)

log = []
def out(s=""):
    print(s); log.append(str(s))

base = df[df.scenario.str.startswith("baseline")]
tgt  = df[df.scenario == TARGET].sort_values("seq_pos").reset_index(drop=True)

out("="*68)
out(f"只用『四攻擊混合』場景 {TARGET} 當測試集")
out("="*68)
out(f"訓練/擬合：純正常 baseline（{len(base)} 行）")
out(f"測試：{TARGET}（{len(tgt)} 行，異常 {int(tgt.label.sum())} 筆）")
out(f"  異常組成：{tgt[tgt.label==1].attack_type.value_counts().to_dict()}")

NUM_FEATS = ["sensor_events_in_sec","dist_ts_occurrence","session_denied_cumcount","is_write_denied"]

def per_type(pred, sub, title):
    true = sub["label"].values; typ = sub["attack_type"].values
    p,r,f,_ = precision_recall_fscore_support(true, pred, average="binary", zero_division=0)
    out(f"\n[{title}] precision={p:.3f} recall={r:.3f} f1={f:.3f}")
    out("  混淆矩陣 [列=真實, 欄=預測]:"); out("  "+str(confusion_matrix(true,pred)).replace("\n","\n  "))
    for a in ["S","T","R","RP"]:
        m = typ==a
        if m.sum()==0: continue
        out(f"    [{a}] {int(pred[m].sum())}/{int(m.sum())} = {pred[m].sum()/m.sum():.0%}")
    nm = true==0
    out(f"    正常誤報 FPR = {int(pred[nm].sum())}/{int(nm.sum())} = {pred[nm].sum()/max(nm.sum(),1):.2%}")

# =========================================================================
# 模型1：IsolationForest（無監督，只用 baseline 的數值特徵擬合）
# =========================================================================
iso = IsolationForest(n_estimators=300, contamination=0.01, random_state=42)
iso.fit(base[NUM_FEATS].fillna(0).values)
iso_pred = (iso.predict(tgt[NUM_FEATS].fillna(0).values) == -1).astype(int)
per_type(iso_pred, tgt, "IsolationForest (無監督)")

# =========================================================================
# 模型2 & 3：DeepLog（整數 vs 語意），只用 baseline 序列訓練
# =========================================================================
def make_windows(seq):
    X,yn,idx=[],[],[]
    for i in range(len(seq)-WINDOW):
        X.append(seq[i:i+WINDOW]); yn.append(seq[i+WINDOW]); idx.append(i+WINDOW)
    return np.array(X),np.array(yn),np.array(idx)

Xtr,ytr=[],[]
for s in base.scenario.unique():
    seq=base[base.scenario==s].sort_values("seq_pos")["tid"].values
    X,y,_=make_windows(seq)
    if len(X): Xtr.append(X); ytr.append(y)
Xtr=np.concatenate(Xtr); ytr=np.concatenate(ytr)

class IntDeepLog(nn.Module):
    def __init__(s,V,h,l):
        super().__init__(); s.emb=nn.Embedding(V,h); s.lstm=nn.LSTM(h,h,l,batch_first=True); s.fc=nn.Linear(h,V)
    def forward(s,x):
        o,_=s.lstm(s.emb(x)); return s.fc(o[:,-1,:])

class SemDeepLog(nn.Module):
    def __init__(s,sem,h,l,V):
        super().__init__()
        s.emb=nn.Embedding.from_pretrained(torch.tensor(sem,dtype=torch.float32),freeze=True)
        s.proj=nn.Linear(sem.shape[1],h); s.lstm=nn.LSTM(h,h,l,batch_first=True); s.fc=nn.Linear(h,V)
    def forward(s,x):
        o,_=s.lstm(s.proj(s.emb(x))); return s.fc(o[:,-1,:])

def train_eval_deeplog(model, tag):
    opt=torch.optim.Adam(filter(lambda p:p.requires_grad,model.parameters()),lr=LR)
    lf=nn.CrossEntropyLoss()
    dl=DataLoader(TensorDataset(torch.tensor(Xtr),torch.tensor(ytr)),batch_size=BATCH,shuffle=True)
    model.train()
    for ep in range(EPOCHS):
        for xb,yb in dl:
            opt.zero_grad(); lf(model(xb),yb).backward(); opt.step()
    model.eval()
    seq=tgt["tid"].values
    X,yn,idxs=make_windows(seq)
    with torch.no_grad():
        topk=torch.topk(model(torch.tensor(X)),TOPK,dim=1).indices.numpy()
    miss=np.array([yn[i] not in topk[i] for i in range(len(yn))]).astype(int)
    sub=tgt.loc[idxs].reset_index(drop=True)
    per_type(miss, sub, tag)

train_eval_deeplog(IntDeepLog(V,HIDDEN,LAYERS), "DeepLog 整數版 (序列)")
sem=np.load(os.path.join(OUT,"template_embeddings.npy"))
train_eval_deeplog(SemDeepLog(sem,HIDDEN,LAYERS,V), "DeepLog 語意版 (序列)")

out("\n"+"="*68)
out("解讀")
out("="*68)
out("- 這是最接近真實的評估：單一時間軸內四種攻擊並存，模型需同時應付。")
out("- 對照『全測試集混合』的總分，可看出 Four_combined 這個高難度場景是否被平均掉。")
out("- 各攻擊類別 recall 仍延續全域結論：S/T 靠序列、RP 靠參數統計、R 為模板洩漏。")

open(os.path.join(OUT,"four_combined_eval.txt"),"w",encoding="utf-8").write("\n".join(str(x) for x in log)+"\n")
print(f"\n報告已存: {OUT}/four_combined_eval.txt")
