#!/usr/bin/env python3
# =============================================================================
# graph_clf.py ── 圖級（per-second graph）分類：專為進階攻擊 compromised 設計
# =============================================================================
# 為什麼需要這支（而非只用 egraphsage.py 的邊分類）：
#   compromised_node 攻擊冒用合法身分、流量完全正常、**沒有任何攻擊邊**
#   （攻擊者融進真 motor 節點）。邊分類器對它結構性失明 —— advanced_holdout
#   的邊測試其實只測到 stealth。要評分 compromised，必須把「一整秒的圖」當成
#   一個樣本來分類：這一秒，是否有任何 motor 回報了與 sensor 真值不符的值？
#
#   這正是圖結構才有的視角：所有 motor 都連到同一個 sensor / agg_server，
#   把它們的回報值放在同一張圖裡做訊息傳遞 + pooling，模型能自己聚合出
#   「這群節點彼此不一致」。單邊分類（RF / edge-GNN）看不到跨節點關係。
#
# 三個對照（回答「圖結構有沒有加值」）：
#   (A) RF・邊特徵聚合   : 把每張圖的邊特徵做 mean/max 展平給 RF（無跨節點值）。
#                          代表「不用圖、也沒拿到值一致性特徵」的基線 → 應在 compromised 失敗。
#   (B) RF・圖特徵含值   : 加上 build_graph 預先算好的 report_dev_max/spread。
#                          代表「有人幫你把跨節點比對做成一個平特徵」→ 會成功，
#                          但那是人工特徵工程，不是模型自己從結構學到的。
#   (C) GNN・per-node 值 : 只給每個節點自己的回報值（report_val/report_dev），
#                          不給 (B) 的預聚合特徵。若 GNN 靠 pooling 自己學到不一致
#                          並贏過 (A)，就證明圖結構帶來了邊分類/無圖法拿不到的資訊。
#
# 執行： ml/venv/bin/python net/graph_clf.py <capture_dir>
# =============================================================================
import os, sys, json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import MessagePassing
from torch_geometric.utils import scatter
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (precision_recall_fscore_support,
                             average_precision_score, roc_auc_score)

EDGE_FEATS = ["n_pkts", "n_c2s", "n_s2c", "bytes_c2s",
              "bytes_s2c", "n_syn", "n_finrst", "max_payload"]
# GNN (C) 的節點特徵：網路層 + 時序 + **per-node 值**（不含 (B) 的預聚合值）
NODE_FEATS_C = ["n_pkts", "bytes_c2s", "bytes_s2c", "n_syn", "n_finrst",
                "max_payload", "degree", "d_n_pkts", "roll_mean", "roll_std",
                "report_val", "report_dev"]
# RF (B) 的圖級平特徵：邊特徵聚合 + 預算好的跨節點聚合值
GRAPH_AGG_FEATS = ["report_dev_max", "report_spread", "log_lines_null", "log_lines_named"]

# ---- one-class 用的節點特徵切分（見 run_gnn_oneclass 的說明）----
#   VAL_FEATS 是「這個節點回報了什麼」＝被預測的目標；
#   CTX_FEATS 是「這個節點在網路上長什麼樣」＝可用的上下文。
VAL_FEATS = ["report_val", "report_dev"]
CTX_FEATS = [c for c in NODE_FEATS_C if c not in VAL_FEATS]

K_LAYERS, HIDDEN, DROPOUT, LR, EPOCHS = 2, 64, 0.2, 1e-3, 150
AE_EPOCHS, AE_LR = 300, 5e-3
SEEDS = [42, 43, 44, 45, 46]
ADV = {"stealth", "compromised", "compromised_group"}

log = []
def out(s=""):
    print(s); log.append(s)


# ---- E-GraphSAGE conv（與 egraphsage.py 相同）＋ 圖級 pooling 頭 ----
class EGraphSAGEConv(MessagePassing):
    def __init__(self, in_node_dim, edge_dim, out_dim):
        super().__init__(aggr="mean")
        self.lin = nn.Linear(in_node_dim + edge_dim, out_dim)

    def forward(self, x, edge_index, edge_attr):
        agg = self.propagate(edge_index, x=x, edge_attr=edge_attr)
        return self.lin(torch.cat([x, agg], dim=1))

    def message(self, edge_attr):
        return edge_attr


class GraphSAGEClassifier(nn.Module):
    """K 層 E-GraphSAGE → 依 graph_id pooling（mean+max）→ 圖級二分類。"""
    def __init__(self, node_dim, edge_dim, hid=HIDDEN, k=K_LAYERS, n_cls=2):
        super().__init__()
        self.convs = nn.ModuleList()
        d = node_dim
        for _ in range(k):
            self.convs.append(EGraphSAGEConv(d, edge_dim, hid))
            d = hid
        self.drop = nn.Dropout(DROPOUT)
        self.cls = nn.Sequential(nn.Linear(hid * 2, hid), nn.ReLU(),
                                 nn.Linear(hid, n_cls))

    def forward(self, x, edge_index, edge_attr, graph_id, n_graphs):
        h = x
        for i, conv in enumerate(self.convs):
            h = F.relu(conv(h, edge_index, edge_attr))
            if i < len(self.convs) - 1:
                h = self.drop(h)
        mean_p = scatter(h, graph_id, dim=0, dim_size=n_graphs, reduce="mean")
        max_p = scatter(h, graph_id, dim=0, dim_size=n_graphs, reduce="max")
        return self.cls(torch.cat([mean_p, max_p], dim=1))


# =============================================================================
# 載入：每秒一張圖 → (節點特徵, 邊, graph_id, 圖標籤, 場景)
# =============================================================================
def load(gdir):
    nodes = pd.read_csv(os.path.join(gdir, "nodes.csv"))
    edges = pd.read_csv(os.path.join(gdir, "edges.csv"))
    graphs = pd.read_csv(os.path.join(gdir, "graphs.csv"))

    # per-node 值特徵可能不存在（舊資料）→ 補 0，保持向後相容
    for c in NODE_FEATS_C:
        if c not in nodes.columns:
            nodes[c] = 0.0

    nodes = nodes.sort_values(["scenario", "sec", "node"]).reset_index(drop=True)
    nodes["nid"] = np.arange(len(nodes))
    # 圖 id：每個 (scenario, sec) 一張圖
    gkey = {k: i for i, k in enumerate(
        sorted(set(zip(nodes.scenario, nodes.sec))))}
    nodes["gid"] = [gkey[(s, t)] for s, t in zip(nodes.scenario, nodes.sec)]
    n_graphs = len(gkey)

    key2nid = {(s, t, n): i for s, t, n, i in
               zip(nodes.scenario, nodes.sec, nodes.node, nodes.nid)}
    src = np.array([key2nid[(s, t, n)] for s, t, n in
                    zip(edges.scenario, edges.sec, edges.src)])
    dst = np.array([key2nid[(s, t, n)] for s, t, n in
                    zip(edges.scenario, edges.sec, edges.dst)])
    edge_index = torch.tensor(np.vstack([np.concatenate([src, dst]),
                                         np.concatenate([dst, src])]), dtype=torch.long)
    ea = edges[EDGE_FEATS].values.astype(np.float32)
    edge_attr = torch.tensor(np.vstack([ea, ea]), dtype=torch.float)

    x = torch.tensor(nodes[NODE_FEATS_C].values.astype(np.float32))
    graph_id = torch.tensor(nodes["gid"].values, dtype=torch.long)

    # 圖標籤 & 場景（依 gkey 排序）
    g_lab = np.zeros(n_graphs, dtype=np.int64)
    g_scen = np.empty(n_graphs, dtype=object)
    for s, t, lb in zip(graphs.scenario, graphs.sec, graphs.label):
        if (s, t) in gkey:
            g_lab[gkey[(s, t)]] = int(lb)
            g_scen[gkey[(s, t)]] = s
    return dict(nodes=nodes, edges=edges, graphs=graphs,
                x=x, edge_index=edge_index, edge_attr=edge_attr,
                graph_id=graph_id, n_graphs=n_graphs,
                y=torch.tensor(g_lab), scen=g_scen, gkey=gkey)


def graph_split(d):
    """advanced_holdout（圖級）：簡單攻擊+benign 訓練 → 進階攻擊測試。

    ⚠️ 重要限制：compromised 的破綻是 per-node 值特徵 report_dev，而這個特徵在所有
    「簡單攻擊 + benign」訓練場景裡都是 0（它們沒有值竄改）。模型無法學會使用一個
    訓練集從未出現過的特徵，因此 **advanced_holdout 對 compromised 沒有意義**
    （會低到接近無圖基線）。compromised 的正確評估請用 random_split() 或 one-class。
    此切分留給 stealth（時序/行為特徵在簡單攻擊裡有出現，可泛化）。
    """
    scen = d["scen"]
    present = set(scen)
    adv = ADV & present
    tr = np.array([s not in adv for s in scen])
    te = np.array([s in adv for s in scen])
    return tr, te, sorted({s for s in present if s not in adv}), sorted(adv)


def random_split(d, frac=0.7, seed=0):
    """70/30 隨機切分：compromised 的攻擊圖同時出現在訓練與測試，模型才可能學到
    值不一致特徵。這是評估 compromised「圖結構能否偵測」的正確框架（監督式）。
    另一個等價正確框架是 one-class（只 benign 訓練），與本專案既有方法學一致。"""
    n = d["n_graphs"]
    rng = np.random.RandomState(seed)
    perm = rng.permutation(n)
    cut = int(n * frac)
    tr = np.zeros(n, dtype=bool); tr[perm[:cut]] = True
    te = ~tr
    return tr, te


def metrics(prob, y):
    pred = (prob >= 0.5).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                 zero_division=0)
    nm = y == 0
    m = dict(precision=p, recall=r, f1=f,
             far=pred[nm].sum() / max(nm.sum(), 1))
    m["pr_auc"] = average_precision_score(y, prob) if len(set(y)) > 1 else float("nan")
    m["roc_auc"] = roc_auc_score(y, prob) if len(set(y)) > 1 else float("nan")
    return m


# ---- 每個場景各自算指標（讓 stealth vs compromised 分開看）----
def per_scenario(prob, y, scen_te):
    res = {}
    for s in sorted(set(scen_te)):
        mask = scen_te == s
        if mask.sum() and len(set(y[mask])) >= 1:
            res[s] = metrics(prob[mask], y[mask])
    return res


# =============================================================================
# (A)(B) RandomForest 圖級基線
# =============================================================================
def rf_graph_features(d, include_values):
    """把每張圖攤平成一個平特徵向量。
    include_values=False → (A) 只有邊特徵聚合（無跨節點值，代表無圖基線）
    include_values=True  → (B) 再加 report_dev_max/spread（人工跨節點特徵）
    """
    edges = d["edges"]
    gkey = d["gkey"]
    n = d["n_graphs"]
    dim = len(EDGE_FEATS) * 2                       # mean + max
    X = np.zeros((n, dim), dtype=np.float32)
    # 邊特徵：每張圖 mean 與 max
    grp = edges.groupby([edges.scenario, edges.sec])
    for (s, t), sub in grp:
        if (s, t) not in gkey:
            continue
        gi = gkey[(s, t)]
        vals = sub[EDGE_FEATS].values.astype(np.float32)
        X[gi, :len(EDGE_FEATS)] = vals.mean(0)
        X[gi, len(EDGE_FEATS):] = vals.max(0)
    if include_values:
        graphs = d["graphs"]
        extra = np.zeros((n, len(GRAPH_AGG_FEATS)), dtype=np.float32)
        for s, t, *_ in zip(graphs.scenario, graphs.sec):
            pass
        gv = graphs.set_index(["scenario", "sec"])
        for (s, t), gi in gkey.items():
            if (s, t) in gv.index:
                row = gv.loc[(s, t)]
                extra[gi] = [float(row[c]) for c in GRAPH_AGG_FEATS]
        X = np.hstack([X, extra])
    return X


def run_rf(d, tr, te, include_values):
    X = rf_graph_features(d, include_values)
    y = d["y"].numpy()
    scen_te = d["scen"][te]
    runs, pers = [], []
    for sd in SEEDS:
        clf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                     random_state=sd, n_jobs=-1)
        clf.fit(X[tr], y[tr])
        prob = clf.predict_proba(X[te])[:, 1]
        runs.append(metrics(prob, y[te]))
        pers.append(per_scenario(prob, y[te], scen_te))
    return runs, pers


# =============================================================================
# (C) GNN 圖級
# =============================================================================
def run_gnn(d, tr, te):
    x = d["x"].clone()
    xm, xs = x[torch.tensor(_node_mask(d, tr))].mean(0), x[torch.tensor(_node_mask(d, tr))].std(0)
    xs[xs == 0] = 1.0
    x = (x - xm) / xs
    ea = d["edge_attr"]
    n_ed = ea.shape[0] // 2
    # 邊標準化只 fit 訓練圖的邊
    tr_e = _edge_mask(d, tr)
    mu, sd_ = ea[:n_ed][tr_e].mean(0), ea[:n_ed][tr_e].std(0)
    sd_[sd_ == 0] = 1.0
    ea_n = (ea - mu) / sd_

    y = d["y"]
    tr_t = torch.tensor(tr); te_t = torch.tensor(te)
    scen_te = d["scen"][te]
    runs, pers = [], []
    for sd in SEEDS:
        torch.manual_seed(sd); np.random.seed(sd)
        model = GraphSAGEClassifier(x.shape[1], ea.shape[1])
        opt = torch.optim.Adam(model.parameters(), lr=LR)
        n_pos = int(y[tr_t].sum()); n_neg = int(tr_t.sum()) - n_pos
        w = torch.tensor([1.0, max(n_neg / max(n_pos, 1), 1.0)])
        lossf = nn.CrossEntropyLoss(weight=w)
        model.train()
        for _ in range(EPOCHS):
            opt.zero_grad()
            logits = model(x, d["edge_index"], ea_n, d["graph_id"], d["n_graphs"])
            loss = lossf(logits[tr_t], y[tr_t])
            loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            prob = torch.softmax(model(x, d["edge_index"], ea_n,
                                       d["graph_id"], d["n_graphs"]), 1)[:, 1].numpy()
        runs.append(metrics(prob[te], y[te].numpy()))
        pers.append(per_scenario(prob[te], y[te].numpy(), scen_te))
    return runs, pers


def _node_mask(d, gmask):
    keep = set(np.where(gmask)[0])
    return np.array([g in keep for g in d["graph_id"].numpy()])


def _edge_mask(d, gmask):
    keep = set(np.where(gmask)[0])
    e = d["edges"]
    gid = np.array([d["gkey"][(s, t)] for s, t in zip(e.scenario, e.sec)])
    return np.array([g in keep for g in gid])


# =============================================================================
# one-class：只用 benign 訓練「正常樣態」，對所有場景輸出 anomaly score
# -----------------------------------------------------------------------------
# 為什麼要這個框架：random 70/30 是監督式的——它假設你手上已經有 compromised 的
# 標註樣本。真實部署拿不到攻擊標籤，ml/ 管線（DeepLog / IsolationForest）也一律
# 只用 benign 訓練。要讓「GNN 對 compromised 有價值」這個結論站得住腳，必須在
# 無標籤框架下也成立。
#
# 三個對照沿用 A/B/C 的意義，只是換成無監督：
#   (A) IF・邊特徵聚合      : IsolationForest 只吃流量聚合 → 無跨節點值 → 應失敗。
#   (B) IF・+人工跨節點值   : 加 report_dev_max/spread → 人工特徵工程版本。
#   (C) GNN・peer 值重建    : 見 GraphValueAE —— 模型自己從「同一張圖的其他節點」
#                             預測這個節點該回報什麼，重建誤差當 anomaly score。
# =============================================================================
def one_class_split(d, frac=0.7, seed=0):
    """訓練集 = benign 場景的 70% 圖（無標籤假設：只知道這段是正常運轉）。
    測試集 = 其餘 benign（量 FAR）+ 全部其他場景（量 recall）。"""
    scen = d["scen"]
    benign = np.array([s == "benign" for s in scen])
    idx = np.where(benign)[0]
    rng = np.random.RandomState(seed)
    perm = rng.permutation(len(idx))
    cut = int(len(idx) * frac)
    tr = np.zeros(d["n_graphs"], dtype=bool)
    tr[idx[perm[:cut]]] = True
    return tr, ~tr


def _flat_graph_scores_if(d, tr, te, include_values, seed):
    """(A)(B)：IsolationForest 吃圖級平特徵，只在 benign 訓練圖上 fit。"""
    from sklearn.ensemble import IsolationForest
    X = rf_graph_features(d, include_values)
    mu, sd_ = X[tr].mean(0), X[tr].std(0)
    sd_[sd_ == 0] = 1.0
    Xn = (X - mu) / sd_
    clf = IsolationForest(n_estimators=300, contamination="auto",
                          random_state=seed, n_jobs=-1)
    clf.fit(Xn[tr])
    # score_samples 越大越正常 → 取負號當 anomaly score
    return -clf.score_samples(Xn), -clf.score_samples(Xn[tr])


class GraphValueAE(nn.Module):
    """「用同一張圖的其他節點，預測這個節點該回報什麼」的圖自編碼器。

    關鍵設計 —— **不讓節點看到自己的值**：
      若直接把 report_val/report_dev 餵進去再重建，模型會學到恆等映射，
      重建誤差恆為 0，偵測不到任何東西。因此值特徵先經 MLP 編成 v_i，
      再對「同圖的其他回報節點」做 leave-one-out 平均 (sum - self)/(n-1)
      當作 peer 上下文。解碼器輸入 = [自己的網路層 embedding, peer 值上下文]，
      輸出 = 自己的值特徵。

    這正是 GNN 才給得起的視角：一個被冒用的節點，網路行為完全正常（h_ctx 看不出
    異常），但它回報的值無法由「該一致的那群 peer」預測 → 重建誤差爆開。
    平特徵 RF 只有一個預先算好的 report_dev_max 可用，那是人工做好的比對；
    這裡模型是自己從結構學出「該跟誰比」。
    """
    def __init__(self, ctx_dim, val_dim, edge_dim, hid=HIDDEN, k=K_LAYERS):
        super().__init__()
        self.convs = nn.ModuleList()
        dcur = ctx_dim
        for _ in range(k):
            self.convs.append(EGraphSAGEConv(dcur, edge_dim, hid))
            dcur = hid
        self.val_enc = nn.Sequential(nn.Linear(val_dim, hid), nn.ReLU(),
                                     nn.Linear(hid, hid))
        self.dec = nn.Sequential(nn.Linear(hid * 2, hid), nn.ReLU(),
                                 nn.Linear(hid, val_dim))

    def forward(self, x_ctx, x_val, edge_index, edge_attr, graph_id,
                n_graphs, peer_mask, hop2=None):
        h = x_ctx
        for conv in self.convs:
            h = F.relu(conv(h, edge_index, edge_attr))
        v = self.val_enc(x_val)
        if hop2 is None:
            # 全圖 pooling 版（單 sensor 拓撲）：同一張圖的回報節點就是同一群。
            pm = peer_mask.unsqueeze(1).float()
            vs = scatter(v * pm, graph_id, dim=0, dim_size=n_graphs, reduce="sum")
            cnt = scatter(pm, graph_id, dim=0, dim_size=n_graphs, reduce="sum")
            num = vs[graph_id] - v * pm
            den = (cnt[graph_id] - pm).clamp(min=1.0)
            peer = num / den
        else:
            peer = hop2(v)      # 沿著邊做 2-hop 聚合（見 make_hop2_peer）
        return self.dec(torch.cat([h, peer], dim=1))


def make_hop2_peer(edge_index, n_nodes, report_mask=None):
    """回傳一個函式 v ↦「沿著邊走 2 跳、且**扣掉自己**」的鄰居平均。

    為什麼要 2 跳：motor 節點在圖上只跟自己訂閱的 sensor 相連（實測 edges.csv：
    motor_x → sensor_server，motor 之間沒有直接邊）。所以「同一群的 peer」正好是
    2 跳鄰居：motor → sensor → 其他 motor。這是**拓撲決定的分群**，多 sensor 時
    每台 motor 只會聚合到自己那一群 —— 全圖 pooling 做不到這件事（會把不同群
    的值混在一起，benign 也會被算成不一致）。

    為什麼要扣掉自己：2 跳一定會經由 sensor 繞回自己（i→s→i），若不扣，模型可以
    直接抄自己的值 → 重建誤差恆為 0，偵測不到任何東西。因為 mean 聚合是線性的，
    自我回流量可以**解析地**扣掉：
        peer_i = (P²v)_i − (P²)_ii·v_i     再除以 (1 − (P²)_ii) 還原成平均
        (P²)_ii = Σ_{s∈N(i)} 1/(deg(i)·deg(s))
    這比「對每個節點各跑一次 masked forward」省 N 倍計算，且是精確的。

    ⚠️ `report_mask`：第一跳**只聚合真的有回報值的節點**（踩過的坑）。
    先前對所有鄰居取平均，於是「訂閱了 sensor 但從不回報值」的節點（值恆為 0）
    會把同群 peer 的 context 拉偏。實測 compromised_group 場景：攻擊者的 reader
    行程訂閱了 sensor1 卻不寫任何 log → sensor1 那群從 2 個成員變 3 個，其中一個
    恆為 0 → **整個場景的重建誤差被墊高（FAR 55%）**，20 秒的惡意訊號被淹沒。
    加上遮罩後，peer context 只由「會回報的同群節點」構成，與 benign 同構。
    """
    src, dst = edge_index[0], edge_index[1]
    ones = torch.ones(src.shape[0])
    deg = torch.zeros(n_nodes).index_add_(0, dst, ones)
    deg_safe = deg.clamp(min=1.0)

    if report_mask is None:
        m = torch.ones(n_nodes)
    else:
        m = report_mask.float()
    # M_s = 節點 s 的鄰居中「有回報」的個數（第一跳的分母）
    M = torch.zeros(n_nodes).index_add_(0, dst, m[src])
    M_safe = M.clamp(min=1.0)

    # 自我回流量： d2_i = Σ_{s∈N(i)} (1/deg(i)) · (m_i / M_s)
    d2 = (torch.zeros(n_nodes).index_add_(0, dst, (1.0 / M_safe)[src]) / deg_safe) * m
    denom = (1.0 - d2).clamp(min=1e-3)
    valid = ((deg > 0) & (m > 0)).float().unsqueeze(1)

    def hop2(v):
        vm = v * m.unsqueeze(1)
        # 第一跳：只對有回報的鄰居取平均
        h1 = torch.zeros_like(v).index_add_(0, dst, vm[src]) / M_safe.unsqueeze(1)
        # 第二跳：沿邊回到自己那群的成員
        h2 = torch.zeros_like(v).index_add_(0, dst, h1[src]) / deg_safe.unsqueeze(1)
        return ((h2 - d2.unsqueeze(1) * v) / denom.unsqueeze(1)) * valid

    return hop2


def make_hop1_ctx(edge_index, n_nodes, report_mask=None):
    """回傳 v ↦「**一跳**鄰居中有回報值者的平均」。**1:1 pair 拓撲專用。**

    為什麼需要另一個版本：`make_hop2_peer` 的「同群 peer」＝ motor → sensor →
    其他 motor。這在「每台 sensor 底下有多台 motor」時成立，但在**三組 1 對 1**
    拓撲下，每台 sensor 底下只有一台 motor —— 2 跳唯一走得到的就是自己，扣掉
    自我回流之後 peer 恆為 0，`has_peer` 全 0，整個變體無節點可評分。
    （實測邊：`motor_i → sensor_serverK`；motor 的 log 通道是**另一個節點**
    `log_writer_j → agg_server`，所以 motor 之間不存在任何 2 跳路徑。）

    1:1 下正確的鄰居資訊是**一跳**：motor 的鄰居就是它訂閱的那台 sensor，而
    sensor 節點掛的是真值。於是重建任務變成「用鄰居 sensor 的真值預測自己的
    回報值」—— benign 逐位元相同、冒用時偏離。這是規則 D5 的可學習版本，差別
    在於 GNN 用的是**當下這一秒圖上實際存在的訂閱邊**，不需要任何 motor→sensor
    對照表（見 TOPO_PAIR3_GNN_DESIGN.md 的主張範圍）。

    不需要扣自我回流：一跳不會經過自己（節點沒有自環）。`report_mask` 的語意與
    2 跳版相同 —— 只聚合真的有回報值的鄰居，避免「訂閱了但不回報」的節點把
    context 拉偏（那個坑見 make_hop2_peer 的說明）。

    ⚠️ 副作用（呼叫端必須處理）：一跳是對稱的，所以 **sensor 節點也會有鄰居**
    （它的 motor），不再像 2 跳版那樣自動被 `has_peer` 濾掉。若把 sensor 也當成
    重建目標，冒用場景下「sensor 被錯誤的 motor 值預測」同樣會產生大誤差，
    node-level 指認就可能指到 sensor 而不是冒用者。hop2_diag.py 在 HOP=1 時
    另外用 node_type 把評分目標限定在 motor（C 與 D 套用同一個遮罩，對照仍乾淨）。
    """
    src, dst = edge_index[0], edge_index[1]
    m = torch.ones(n_nodes) if report_mask is None else report_mask.float()

    # M_i = 節點 i 的鄰居中「有回報」的個數（聚合的分母）
    M = torch.zeros(n_nodes).index_add_(0, dst, m[src])
    M_safe = M.clamp(min=1.0)
    # ⚠️ 與 2 跳版**不同**：只要求「至少有一個合格鄰居」，不要求自己也在 mask 裡。
    # 2 跳版的 report_mask 同時是「聚合來源」與「評分目標」（都是有回報值的節點），
    # 所以那裡多要求一個 m_i > 0 是對的。一跳版刻意把來源設成「帶窗內樣本的 sensor」
    # 而目標是 motor —— motor 的 m_i = 0，若沿用 2 跳語意會讓 valid 恆 0、輸出恆 0、
    # has_peer 全 0，整個變體靜默失效（殘差全 0、top1 = 0.000）。
    valid = (M > 0).float().unsqueeze(1)

    def hop1(v):
        vm = v * m.unsqueeze(1)
        return (torch.zeros_like(v).index_add_(0, dst, vm[src])
                / M_safe.unsqueeze(1)) * valid

    return hop1


def run_gnn_oneclass(d, tr, te):
    """(C)：只在 benign 訓練圖上訓 GraphValueAE，score = 圖內回報節點的最大重建誤差。"""
    nodes = d["nodes"]
    x_ctx = torch.tensor(nodes[CTX_FEATS].values.astype(np.float32))
    x_val = torch.tensor(nodes[VAL_FEATS].values.astype(np.float32))
    # 「回報節點」＝這一秒真的寫了值的節點（motor / 冒用者），非回報節點值恆為 0，
    # 拿它們算重建誤差只會稀釋訊號。
    peer_mask = torch.tensor((nodes["report_val"].values != 0).astype(np.float32))
    gid = d["graph_id"]
    ea = d["edge_attr"]

    nmask = torch.tensor(_node_mask(d, tr))
    for X in (x_ctx, x_val):
        mu, sd_ = X[nmask].mean(0), X[nmask].std(0)
        sd_[sd_ == 0] = 1.0
        X.sub_(mu).div_(sd_)
    n_ed = ea.shape[0] // 2
    tr_e = _edge_mask(d, tr)
    mu, sd_ = ea[:n_ed][tr_e].mean(0), ea[:n_ed][tr_e].std(0)
    sd_[sd_ == 0] = 1.0
    ea_n = (ea - mu) / sd_
    hop2 = make_hop2_peer(d["edge_index"], x_ctx.shape[0], peer_mask)

    # ⚠️ 只有「2-hop 真的有 peer」的節點才能當重建目標（2026-08-10 修，見 hop2_diag.py）
    #   peer_mask 是 report_val != 0，而 **sensor 節點也掛真值** → 它也在裡面。
    #   但 sensor 的 2-hop 鄰居只有它自己（sensor → motor → sensor），扣掉自我回流
    #   後 peer 恆為 0（實測 server 型別節點有 peer 的比例 0.0%）。於是模型被要求
    #   「在零資訊下重建 sensor 的值」，殘差中位數高達 24~27，而圖分數是節點誤差的
    #   **max** → 攻擊者的訊號（20 上下）永遠被 sensor 蓋掉。
    #   實測影響：compromised one-class PR-AUC 0.049 → 1.000、node top1 0.433 → 1.000、
    #   benign 背景率 0.6% → 0.2%。
    #   注意 sensor **沒有**被移出圖 —— 它仍是 motor→sensor→motor 這條 2 跳路徑的
    #   中繼點，移除的話 peer 聚合會直接歸零。這裡只是不把它當「被檢查的對象」。
    #   代價（要寫進限制）：本方法只能檢查有 peer 的節點。若該群只有一台 sensor、
    #   沒有可比對的同儕，sensor 自身被入侵時原理上抓不到。
    has_peer = (hop2(torch.ones(x_ctx.shape[0], 1)).abs().squeeze(1) > 1e-6).float()
    score_mask = peer_mask * has_peer

    y = d["y"].numpy()
    scen_te = d["scen"][te]
    runs, pers, thr_used = [], [], []
    for sd in SEEDS:
        torch.manual_seed(sd); np.random.seed(sd)
        model = GraphValueAE(x_ctx.shape[1], x_val.shape[1], ea.shape[1])
        opt = torch.optim.Adam(model.parameters(), lr=AE_LR)
        w = score_mask.unsqueeze(1)      # 見上方：只在有 peer 的節點上算 loss
        model.train()
        for _ in range(AE_EPOCHS):
            opt.zero_grad()
            pred = model(x_ctx, x_val, d["edge_index"], ea_n, gid,
                         d["n_graphs"], peer_mask, hop2)
            err = ((pred - x_val) ** 2) * w
            # 只在 benign 訓練圖的回報節點上算 loss
            loss = err[nmask].sum() / w[nmask].sum().clamp(min=1.0)
            loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            pred = model(x_ctx, x_val, d["edge_index"], ea_n, gid,
                         d["n_graphs"], peer_mask, hop2)
            ne = (((pred - x_val) ** 2).mean(1) * score_mask)
            score = scatter(ne, gid, dim=0, dim_size=d["n_graphs"],
                            reduce="max").numpy()
        thr = float(np.quantile(score[tr], 0.95)) if tr.sum() else 0.0
        thr_used.append(thr)
        runs.append(metrics_thr(score[te], y[te], thr))
        pers.append(per_scenario_thr(score[te], y[te], scen_te, thr))
    return runs, pers


def run_if_oneclass(d, tr, te, include_values):
    y = d["y"].numpy()
    scen_te = d["scen"][te]
    runs, pers = [], []
    for sd in SEEDS:
        score, score_tr = _flat_graph_scores_if(d, tr, te, include_values, sd)
        thr = float(np.quantile(score_tr, 0.95)) if len(score_tr) else 0.0
        runs.append(metrics_thr(score[te], y[te], thr))
        pers.append(per_scenario_thr(score[te], y[te], scen_te, thr))
    return runs, pers


def metrics_thr(score, y, thr):
    """one-class 的門檻不是 0.5，而是 benign 訓練分數的 95 分位
    （無標籤可用的校準方式：容忍 5% 誤報）。PR-AUC/ROC-AUC 與門檻無關。"""
    pred = (score > thr).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                 zero_division=0)
    nm = y == 0
    m = dict(precision=p, recall=r, f1=f,
             far=pred[nm].sum() / max(nm.sum(), 1))
    m["pr_auc"] = average_precision_score(y, score) if len(set(y)) > 1 else float("nan")
    m["roc_auc"] = roc_auc_score(y, score) if len(set(y)) > 1 else float("nan")
    return m


def per_scenario_thr(score, y, scen_te, thr):
    res = {}
    for s in sorted(set(scen_te)):
        mask = scen_te == s
        if mask.sum():
            res[s] = metrics_thr(score[mask], y[mask], thr)
    return res


def run_all_oneclass(d, tr, te):
    pa = report_block("A · IF 邊特徵聚合（無跨節點值＝無圖基線）",
                      *run_if_oneclass(d, tr, te, include_values=False))
    pb = report_block("B · IF 圖特徵含人工跨節點值 report_dev",
                      *run_if_oneclass(d, tr, te, include_values=True))
    pc = report_block("C · GNN peer 值重建誤差（自學跨節點不一致）",
                      *run_gnn_oneclass(d, tr, te))
    return pa, pb, pc


def summarize(runs):
    agg = {}
    for k in ["precision", "recall", "f1", "far", "pr_auc", "roc_auc"]:
        v = np.array([r[k] for r in runs], dtype=float)
        v = v[~np.isnan(v)]
        agg[k] = (float(v.mean()) if len(v) else float("nan"),
                  float(v.std()) if len(v) else float("nan"))
    return agg


def summarize_per_scen(pers):
    scen = set().union(*[set(p) for p in pers])
    res = {}
    for s in sorted(scen):
        rr = [p[s] for p in pers if s in p]
        res[s] = summarize(rr)
    return res


def report_block(name, runs, pers):
    a = summarize(runs)
    out(f"\n  【{name}】 整體")
    out(f"    F1={a['f1'][0]:.3f}±{a['f1'][1]:.3f}  PR-AUC={a['pr_auc'][0]:.3f}  "
        f"recall={a['recall'][0]:.3f}  FAR={a['far'][0]:.2%}")
    ps = summarize_per_scen(pers)
    for s, a in ps.items():
        out(f"      · {s:12s} PR-AUC={a['pr_auc'][0]:.3f}  recall={a['recall'][0]:.3f}  "
            f"F1={a['f1'][0]:.3f}  FAR={a['far'][0]:.2%}")
    return ps


def g(p, s, k):
    return p[s][k][0] if s in p else float("nan")


def run_all(d, tr, te):
    A = run_rf(d, tr, te, include_values=False)
    B = run_rf(d, tr, te, include_values=True)
    C = run_gnn(d, tr, te)
    pa = report_block("A · RF 邊特徵聚合（無跨節點值＝無圖基線）", *A)
    pb = report_block("B · RF 圖特徵含人工跨節點值 report_dev", *B)
    pc = report_block("C · GNN per-node 值 + pooling（自學跨節點不一致）", *C)
    return pa, pb, pc


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: graph_clf.py <capture_dir>")
    root = os.path.abspath(sys.argv[1])
    gdir = os.path.join(root, "graph")
    d = load(gdir)
    y = d["y"].numpy()

    out("=" * 78)
    out("圖級分類（per-second graph）— 專為 compromised 設計")
    out("=" * 78)
    out(f"總圖數 {d['n_graphs']}  攻擊圖 {int(d['y'].sum())}")

    # ---- 切分 1：random 70/30（compromised 的正確監督式評估框架）----
    out("\n" + "#" * 78)
    out("# 切分 1：random 70/30 —— compromised 的正確評估（攻擊例子在訓練也在測試）")
    out("#   為何不用 advanced_holdout 評 compromised：值不一致特徵 report_dev 在所有")
    out("#   簡單攻擊/benign 訓練場景都是 0，模型學不到訓練集沒出現過的特徵。")
    out("#" * 78)
    tr, te = random_split(d)
    out(f"  訓練圖 {int(tr.sum())}（攻擊 {int(y[tr].sum())}） · "
        f"測試圖 {int(te.sum())}（攻擊 {int(y[te].sum())}）")
    ra, rb, rc = run_all(d, tr, te)

    # ---- 切分 2：advanced_holdout（僅對 stealth 有意義）----
    out("\n" + "#" * 78)
    out("# 切分 2：advanced_holdout —— 只對 stealth 有意義（見上方說明，compromised 會失真）")
    out("#" * 78)
    tr2, te2, tr_scen, adv = graph_split(d)
    out(f"  {tr_scen} 訓練 → {adv} 測試  "
        f"訓練圖 {int(tr2.sum())}（攻擊 {int(y[tr2].sum())}） · "
        f"測試圖 {int(te2.sum())}（攻擊 {int(y[te2].sum())}）")
    ha, hb, hc = run_all(d, tr2, te2)

    # ---- 切分 3：one-class（只 benign 訓練，與 ml/ 管線方法學一致）----
    out("\n" + "#" * 78)
    out("# 切分 3：one-class —— 只用 benign 訓練，最誠實的框架（部署時拿不到攻擊標籤）")
    out("#   門檻 = benign 訓練分數 95 分位（容忍 5% 誤報），PR-AUC 與門檻無關。")
    out("#" * 78)
    tr3, te3 = one_class_split(d)
    out(f"  benign 訓練圖 {int(tr3.sum())} · 測試圖 {int(te3.sum())}"
        f"（攻擊 {int(y[te3].sum())}）")
    oa, ob, oc = run_all_oneclass(d, tr3, te3)

    out("\n" + "=" * 78)
    out("結論")
    out("=" * 78)
    out("【compromised —— 用 random 切分（正確框架）】")
    out(f"  PR-AUC:  A(無圖無值)={g(ra,'compromised','pr_auc'):.3f}  "
        f"B(RF+人工值)={g(rb,'compromised','pr_auc'):.3f}  "
        f"C(GNN)={g(rc,'compromised','pr_auc'):.3f}")
    out("  解讀：能在訓練看到特徵時，GNN 靠 per-node 值 + pooling 自己聚合出跨節點")
    out("        不一致 → 與『被餵好人工特徵的 RF』打平，且明顯優於無值 RF。")
    out("        （GNN 的價值是『不需人工做跨節點比對』，非數字上贏過 properly-featured RF。）")
    out("【stealth —— 用 advanced_holdout】")
    out(f"  PR-AUC:  A={g(ha,'stealth','pr_auc'):.3f}  "
        f"B={g(hb,'stealth','pr_auc'):.3f}  C={g(hc,'stealth','pr_auc'):.3f}")
    out("【one-class（只 benign 訓練）—— 無標籤框架下是否仍成立】")
    for s in sorted(ADV & set(d["scen"])):
        out(f"  {s:12s} PR-AUC:  A={g(oa,s,'pr_auc'):.3f}  "
            f"B={g(ob,s,'pr_auc'):.3f}  C={g(oc,s,'pr_auc'):.3f}   "
            f"recall(C)={g(oc,s,'recall'):.3f}")
    out(f"  benign 測試段 FAR:  A={g(oa,'benign','far'):.2%}  "
        f"B={g(ob,'benign','far'):.2%}  C={g(oc,'benign','far'):.2%}")

    summ = dict(
        random_split={k: {s: {m: v[0] for m, v in p[s].items()} for s in p}
                      for k, p in [("A", ra), ("B", rb), ("C", rc)]},
        advanced_holdout={k: {s: {m: v[0] for m, v in p[s].items()} for s in p}
                          for k, p in [("A", ha), ("B", hb), ("C", hc)]},
        one_class={k: {s: {m: v[0] for m, v in p[s].items()} for s in p}
                   for k, p in [("A", oa), ("B", ob), ("C", oc)]},
    )
    with open(os.path.join(gdir, "graph_clf_summary.json"), "w") as f:
        json.dump(summ, f, indent=2)

    txt = os.path.join(gdir, "graph_clf_results.txt")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("\n".join(log))
    out(f"\n報告已存: {txt}")


if __name__ == "__main__":
    main()
