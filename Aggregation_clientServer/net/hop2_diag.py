#!/usr/bin/env python3
# =============================================================================
# hop2_diag.py ── 診斷：peer 聚合為什麼對偵測沒有貢獻（第三輪 P2）
# =============================================================================
# 前置查證（已完成，見下方「查證結果」）：
#   1. 同群 motor 的回報值在 benign 是**逐位元相同**（相關 1.000、差中位數 0.00）
#      → peer 在原理上是完美預測器，資訊絕對存在。
#   2. make_hop2_peer 的輸出**完全正確**：100% 的秒數送出的就是真正的同群 peer。
#      → 2-hop 解析扣除自我回流的公式沒有 bug。
#
# 那為什麼 gnn_ablation 的 V1（有圖、只有 report_val）≈ V3（無圖）？
#
# ── 假設：重建目標裡混進了「沒有 peer 可用」的節點 ──────────────────────────
#   peer_mask = (report_val != 0)，而 **sensor 節點也有 report_val**（它掛真值）。
#   但 sensor 的 2-hop 鄰居只有它自己（sensor → motor → sensor），扣掉自我回流
#   之後 peer 恆為 0 —— 實測 sensor 節點的 hop2 輸出 100% 是 0。
#   於是模型被要求「在零資訊下重建 sensor 的值」，那必然是大誤差；而圖分數是
#   節點誤差的 **max** → 3 個永遠測不準的 sensor 蓋掉攻擊者的訊號。
#   這也解釋了為什麼「有圖」的背景率反而比「無圖」高（噪音來自 sensor 不是 peer）。
#
# ── 本腳本比較兩個變體（其餘完全相同）────────────────────────────────────
#   A 現況      ：loss 與 score 都涵蓋所有 report_val != 0 的節點（含 sensor）
#   B 只算有 peer：loss 與 score 都只涵蓋「2-hop 真的有 peer」的節點（只有 motor）
#
#   若 B ≫ A → V1≈V3 是這個 bug 造成的，「訊息傳遞貢獻為零」的結論必須撤回。
#   若 B ≈ A → peer 資訊確實存在但模型用不上，問題在解碼器/訓練，需另外查。
#
# ── HOP=1：三組 1 對 1 pair 拓撲（TOPO_PAIR3_GNN_DESIGN.md）───────────────────
#   上面整套診斷預設 peer = **2 跳**（motor → sensor → 同群其他 motor）。這在
#   「每台 sensor 底下有多台 motor」時才成立。1:1 拓撲下每群只有一台 motor，
#   2 跳唯一走得到的是自己，扣掉自我回流後 has_peer 全 0 → B/C/D 全部無節點可
#   評分，會得到「GNN 全掛」的**假陰性**。
#
#   `HOP=1` 改用 make_hop1_ctx：鄰居＝自己訂閱的那台 sensor（掛真值），任務變成
#   「用鄰居的真值重建自己的回報值」。同時把評分目標限定在 node_type == motor
#   （見下方 TARGET_TYPES）—— 因為一跳是對稱的，sensor 也會有鄰居，不再像 2 跳
#   版那樣自動被濾掉，留著會讓 node-level 指認指到 sensor 而不是冒用者。
#   遮罩對 C 與 D 完全相同，所以「唯一差別是有沒有訊息傳遞」的對照仍然成立。
#
# ── ⭐ 責任切分：這支腳本負責哪一半（2026-08-12 實測後定案）──────────────────
#   HOP=1 的值一致性檢查是**確定性的，不是學來的**。實測依據：
#     · oracle（完全不訓練，直接對真實 cand 取 min）在 3s6m 上 PR-AUC = 1.000、
#       benign 一萬多列殘差精確為 0 → 訊號完整存在於「一跳鄰居的窗內樣本」裡。
#     · 加上 skip connection 後，恆等解 ĝ = cand 在 benign 上已是最優，
#       loss 從 epoch 0 就是 0 → 梯度為 0 → δ 恆為 0，模型什麼都沒學。
#       （報告區塊會把 δ 印出來，讓這件事是量測到的事實而非宣稱。）
#   這不是缺陷，是任務性質：one-class 只在 benign 訓練，而「預測你正在抄的值」
#   的答案已經當作輸入遞給模型了，恆等解必然最優。
#
#   ⇒ 於是兩類攻擊分開負責，不要互相冒充：
#       compromised*（值冒用）  → 本腳本 HOP=1。主張＝**拓撲韌性**：比較對象由
#                                 當秒圖上的訂閱邊決定，不需要靜態 motor→sensor
#                                 對照表；規則版需要，拓撲一變就靜默失效。
#       S/T/R/RP/stealth（流量）→ graph_clf.py。⚠️ 2026-08-13 實測**推翻**了
#                                 「GNN 在流量型攻擊上真的有在學」這個猜測：
#                                 one-class 的 C 是「peer 值重建誤差」，對不改值的
#                                 流量攻擊**結構性地瞎**（R/RP/S/T/all 的 PR-AUC
#                                 0.002~0.018、recall 全 0）；而監督式切分下 S/T/all
#                                 光用 RF 邊特徵（無圖）就已經 1.000，圖沒有加值空間。
#                                 R/RP 則是所有方法都低。stealth 全軍覆沒（~0.03）。
#                                 ⇒ 本專案目前**唯一**站得住的圖結構價值是下面這條
#                                 「拓撲韌性」，不要再宣稱流量型那半。
#   詳見 TOPO_PAIR3_GNN_DESIGN.md 與 SESSION_20260812_pair3_gnn.md。
#
# 執行： ml/venv/bin/python net/hop2_diag.py <capture_dir>            # 2 跳（3s6m）
#        HOP=1 ATTACKER=motor_3 ml/venv/bin/python net/hop2_diag.py <capture_dir>
# 輸出： <capture_dir>/graph/hop2_diag_results.txt（HOP=1 時檔名加 _hop1）
# =============================================================================
import os, sys
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import average_precision_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import graph_clf as gc

SEEDS = [42, 43, 44]
BUDGET = 0.999
VAL_FEATS = ["report_val"]          # 沿用 V1：不給 report_dev（避免答案外洩）
ATTACKER = os.environ.get("ATTACKER", "motor_7")
# 要評估哪些攻擊場景。留空 = 從資料自動挑（所有含冒用者的 compromised* 場景），
# 這樣 3-4 的 compromised_rot 不必改碼就能跑。可用 SCENS=a,b 覆寫。
SCENS_ENV = os.environ.get("SCENS", "")

# HOP=2（預設）：同群 peer，多對多拓撲用。HOP=1：一跳鄰居 sensor，1:1 pair 拓撲用。
HOP = int(os.environ.get("HOP", "2"))
# HOP=1 才生效：把重建/評分目標限定在這些 node_type（見檔頭說明）。
TARGET_TYPES = [t for t in os.environ.get("TARGET_TYPES", "motor").split(",") if t]


def make_ctx(edge_index, n_nodes, report_mask):
    """依 HOP 選聚合器。兩者介面相同（v ↦ 鄰居 context），呼叫端不必分支。"""
    if HOP == 1:
        return gc.make_hop1_ctx(edge_index, n_nodes, report_mask)
    return gc.make_hop2_peer(edge_index, n_nodes, report_mask)


WIN_FEATS = ["win_val_prev", "win_val_cur", "win_val_next"]


class PairMatchAE(nn.Module):
    """HOP=1（1:1 pair 拓撲）專用：**對候選集合取 min** 的重建模型。

    為什麼不能沿用 GraphValueAE：它是單點重建（預測一個值、算平方誤差）。
    1:1 下鄰居只有自己那台 sensor，而 honest motor 抄的是窗內三筆樣本中的
    **某一筆**（相鄰樣本差 ~13）。單點預測最好只能輸出三者的折衷，benign
    殘差就有 ~6.5，與攻擊訊號（~20）混在一起。

    改成集合式：模型從 [自己的網路 embedding h, 鄰居送來的候選樣本 cand]
    預測 K 個候選值，殘差取 **min_k (v − ĝ_k)²**（Chamfer 式的集合匹配損失）。
    benign 只要有一個候選對上就 → 0；冒用者對所有候選都差 → 殘差爆開。

    誠實邊界（必須寫進報告）：
      · 「取 min」這個匹配運算子是**我們給的**，不是模型學的 —— 學的是
        「要讀哪些鄰居、怎麼把鄰居樣本映射成候選」。規則版 D5 做同一件比對，
        差別在於它需要一份 motor→sensor 對照表，而這裡的鄰居是由**當下這一秒
        圖上實際存在的訂閱邊**決定的。主張仍限於「拓撲韌性」，不是「偵測力更強」。
      · cand 完全由鄰居 sensor 的樣本構成，不含本節點的回報值 → 沒有答案外洩。
        對照組 D 拿不到 cand（恆 0），這與 2 跳版 C/D 的對照方式一致。
    """
    def __init__(self, ctx_dim, edge_dim, k_cand, hid=gc.HIDDEN, k=gc.K_LAYERS):
        super().__init__()
        self.convs = nn.ModuleList()
        dcur = ctx_dim
        for _ in range(k):
            self.convs.append(gc.EGraphSAGEConv(dcur, edge_dim, hid))
            dcur = hid
        self.cand_enc = nn.Sequential(nn.Linear(k_cand, hid), nn.ReLU())
        self.head = nn.Sequential(nn.Linear(hid * 2, hid), nn.ReLU(),
                                  nn.Linear(hid, k_cand))
        # δ 從 0 出發：初始 ĝ_k = cand_k（恆等），模型只學「要修正多少」。
        nn.init.zeros_(self.head[-1].weight); nn.init.zeros_(self.head[-1].bias)

    def forward(self, x_ctx, edge_index, edge_attr, cand):
        """ĝ_k = cand_k + δ_k(h, cand) —— **殘差式**，不是自由生成。

        ⚠️ 為什麼一定要這條 skip connection（2026-08-12 實測的失效）：
        原本 head 直接自由輸出 K 個值，模型於是把三個輸出**塌成同一個**
        （散度 0.0997 vs 真實候選 1.4877），等於把自己退化成單點預測，
        `min_k` 這道保險是模型自己拆掉的。後果：benign 上殘差 0.0002 很漂亮，
        但 benign 的 honest motor 抄的永遠是 prev、compromised 場景變成 cur，
        模型學到的「輸出 prev」常數規則整個平移一格 → 攻擊場景的**誠實** motor
        殘差爆到 3.86（訊號才 0.029）→ 圖級 PR-AUC 歸零。
        oracle（直接對真實 cand 取 min）在同一份資料上是 1.000，因為取 min
        對「抄了窗內哪一筆」的相位免疫 —— 錨在 cand 上才保得住這個免疫力。
        """
        h = x_ctx
        for conv in self.convs:
            h = F.relu(conv(h, edge_index, edge_attr))
        delta = self.head(torch.cat([h, self.cand_enc(cand)], dim=1))
        return cand + delta


def target_mask(nodes):
    """HOP=1 的評分目標遮罩（HOP=2 時恆為 1，行為與改動前完全相同）。"""
    if HOP != 1:
        return torch.ones(len(nodes))
    return torch.tensor(
        np.isin(nodes.node_type.values, TARGET_TYPES).astype(np.float32))


log = []
def out(s=""):
    print(s); log.append(str(s))


def run(d, tr, seed, peer_only, drop_dev=False, use_graph=True):
    """peer_only=False → 變體 A（現況）；True → 變體 B（只算有 peer 的節點）。

    drop_dev=True → 把 report_dev 從 **ctx 與 val 兩側都拿掉**。
    ⚠ 這個選項是必要的：CTX_FEATS 的定義是「NODE_FEATS_C 扣掉 VAL_FEATS」，
    所以只把 report_dev 移出 VAL_FEATS 並不會讓它消失 —— 它會被推到 context
    那一側，模型照樣看得到。gnn_ablation 的 V1/V3 都有這個缺陷，其「已經拿掉
    答案」的宣稱不成立。要主張分數不是來自洩漏，必須用 drop_dev=True 重測。
    """
    nodes = d["nodes"]
    ctx = [c for c in gc.NODE_FEATS_C if c not in VAL_FEATS]
    if drop_dev:
        ctx = [c for c in ctx if c != "report_dev"]
    x_ctx = torch.tensor(nodes[ctx].values.astype(np.float32))
    x_val = torch.tensor(nodes[VAL_FEATS].values.astype(np.float32))
    rep = torch.tensor((nodes["report_val"].values != 0).astype(np.float32))
    gid, ea, ei = d["graph_id"], d["edge_attr"], d["edge_index"]

    nmask = torch.tensor(gc._node_mask(d, tr))
    val_mu = val_sd = None
    for tag, X in (("ctx", x_ctx), ("val", x_val)):
        mu, sd_ = X[nmask].mean(0), X[nmask].std(0)
        sd_[sd_ == 0] = 1.0
        if tag == "val":
            val_mu, val_sd = mu.clone(), sd_.clone()
        X.sub_(mu).div_(sd_)

    # ---- HOP=1：sensor 的窗內樣本，換算到與 report_val **同一組尺度** ----
    # 尺度必須共用，否則 (v − cand) 這個差沒有意義。非 sensor 的列一律歸零，
    # 讓一跳聚合的來源乾淨地只有「帶樣本的 sensor 鄰居」。
    x_win = win_mask = None
    if HOP == 1:
        missing = [c for c in WIN_FEATS if c not in nodes.columns]
        if missing:
            sys.exit(f"nodes.csv 缺少 {missing} —— 舊資料集請先跑 "
                     f"net/backfill_win_feats.py，新採集用改版後的 build_graph.py")
        x_win = torch.tensor(nodes[WIN_FEATS].values.astype(np.float32))
        is_sensor = torch.tensor(
            nodes.node.astype(str).str.startswith("sensor_server").values)
        win_mask = (is_sensor & (x_win.abs().sum(1) > 0)).float()
        x_win = (x_win - val_mu) / val_sd
        x_win = x_win * win_mask.unsqueeze(1)

    n_ed = ea.shape[0] // 2
    tr_e = gc._edge_mask(d, tr)
    mu, sd_ = ea[:n_ed][tr_e].mean(0), ea[:n_ed][tr_e].std(0)
    sd_[sd_ == 0] = 1.0
    ea_n = (ea - mu) / sd_
    # HOP=1 的聚合來源＝「帶窗內樣本的 sensor 鄰居」；HOP=2 沿用 report_mask=rep。
    hop2 = make_ctx(d["edge_index"], x_ctx.shape[0],
                    win_mask if HOP == 1 else rep)

    # 「這個節點的 peer 是否真的帶資訊」—— 用一個常數探針測，
    # 輸出非零才代表它有 peer。2 跳版的 sensor 節點在此一律是 0（見檔頭）。
    probe = hop2(torch.ones(x_ctx.shape[0], 1))
    has_peer = (probe.abs().squeeze(1) > 1e-6).float()
    score_mask = rep * has_peer if peer_only else rep
    # HOP=1：一跳是對稱的，sensor 也會有 peer → 額外用 node_type 限定評分目標。
    # C 與 D 套用同一個遮罩，所以「唯一差別是有沒有訊息傳遞」的對照仍成立。
    score_mask = score_mask * target_mask(nodes)

    # 變體 D 的關鍵對照：拿掉訊息傳遞，但**評分節點集合與 C 完全相同**
    #（has_peer 仍由真實圖算出）。這樣 C 與 D 的唯一差別就只有「有沒有 peer 上下文」，
    # 才能回答「1.000 是來自圖，還是光是只評分 motor 就夠了」。
    if not use_graph:
        idx = torch.arange(x_ctx.shape[0], dtype=torch.long)
        ei = torch.vstack([idx, idx])            # 只剩自環
        ea_n = torch.zeros(x_ctx.shape[0], ea.shape[1])
        hop2 = lambda v: torch.zeros_like(v)     # peer 上下文恆為 0

    torch.manual_seed(seed); np.random.seed(seed)
    w = score_mask.unsqueeze(1)
    diag = {}

    if HOP == 1:
        # 集合式匹配：候選＝鄰居 sensor 的窗內樣本，殘差取 min_k（見 PairMatchAE）
        cand = hop2(x_win)                       # D 變體時 hop2 恆 0 → cand 全 0
        model = PairMatchAE(x_ctx.shape[1], ea.shape[1], len(WIN_FEATS))
        opt = torch.optim.Adam(model.parameters(), lr=gc.AE_LR)
        v = x_val[:, 0]
        model.train()
        for _ in range(gc.AE_EPOCHS):
            opt.zero_grad()
            g = model(x_ctx, ei, ea_n, cand)
            resid = ((v.unsqueeze(1) - g) ** 2).min(dim=1).values
            e = resid * score_mask
            (e[nmask].sum() / score_mask[nmask].sum().clamp(min=1.0)).backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            g = model(x_ctx, ei, ea_n, cand)
            ne = (((v.unsqueeze(1) - g) ** 2).min(dim=1).values
                  * score_mask).numpy()
            # ⭐ 誠實性量測（見檔頭「責任切分」）：δ = ĝ − cand 就是模型**學到**的
            # 修正量。恆等解 ĝ = cand 在 benign 上已經是最優（loss 從 epoch 0 就是
            # 0、梯度為 0），所以這裡預期 δ ≈ 0 —— 也就是這條路徑的偵測力**不是
            # 學來的**，而是圖結構決定了比較對象。這個數字必須印進報告，讓
            # 「這是確定性檢查」變成量測到的事實，而不是註解裡的宣稱。
            sm_b = score_mask > 0
            delta = (g - cand)[sm_b].abs()
            diag["delta_med"] = float(delta.median())
            diag["delta_p95"] = float(delta.flatten().quantile(0.95))
            diag["v_sd"] = float(v[sm_b].std())
    else:
        model = gc.GraphValueAE(x_ctx.shape[1], x_val.shape[1], ea.shape[1])
        opt = torch.optim.Adam(model.parameters(), lr=gc.AE_LR)
        model.train()
        for _ in range(gc.AE_EPOCHS):
            opt.zero_grad()
            pred = model(x_ctx, x_val, ei, ea_n, gid, d["n_graphs"], rep, hop2)
            err = ((pred - x_val) ** 2) * w
            (err[nmask].sum() / w[nmask].sum().clamp(min=1.0)).backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            pred = model(x_ctx, x_val, ei, ea_n, gid, d["n_graphs"], rep, hop2)
            ne = (((pred - x_val) ** 2).mean(1) * score_mask).numpy()

    # node-level top1 的隨機基準要用「真正可被選中」的節點集合來算（見 main）
    diag["score_mask"] = score_mask.numpy()

    gs = gc.scatter(torch.tensor(ne), gid, dim=0,
                    dim_size=d["n_graphs"], reduce="max").numpy()
    return ne, gs, has_peer.numpy(), rep.numpy(), diag


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                           "net/captures/topo_3s6m_20260809_015509")
    gdir = os.path.join(root, "graph")
    d = gc.load(gdir)
    tr, te = gc.one_class_split(d)
    y, scen = d["y"].numpy(), d["scen"]
    nodes = d["nodes"]

    # 評估場景：冒用型攻擊（值不一致）才是本診斷的對象；S/R/RP/T 是流量型，
    # 由規則層負責，放進來只會稀釋表格。
    if SCENS_ENV:
        SCENS = [s for s in SCENS_ENV.split(",") if s]
    else:
        SCENS = sorted({s for s in set(scen) if s.startswith("compromised")})
    if not SCENS:
        sys.exit("找不到 compromised* 場景（可用 SCENS=... 指定）")

    out("=" * 78)
    out("hop2 診斷：peer 聚合為什麼對偵測沒有貢獻")
    out("=" * 78)
    out(f"資料 {root}")

    # ---- 查證 1/2：hop2 正確性與 peer 的資訊量（不需訓練）----
    rep_np = (nodes["report_val"].values != 0)
    pm = torch.tensor(rep_np.astype(np.float32))
    hop2 = make_ctx(d["edge_index"], len(nodes), pm)
    probe = hop2(torch.ones(len(nodes), 1)).abs().squeeze(1).numpy()
    out(f"\n模式 HOP={HOP}"
        + (f"（一跳鄰居 sensor；評分目標限定 node_type ∈ {TARGET_TYPES}）"
           if HOP == 1 else "（2 跳同群 peer）"))
    out(f"\n【查證】哪些節點真的有 {HOP}-hop peer")
    for nt in sorted(set(nodes.node_type[rep_np])):
        m = rep_np & (nodes.node_type.values == nt)
        out(f"  {nt:<14} 有值節點 {int(m.sum()):>6}   其中有 peer 的比例 "
            f"{(probe[m] > 1e-6).mean():>6.1%}")

    # ---- 兩個變體 ----
    # 想只跑部分變體以節省時間： VARIANTS=C,D ml/venv/bin/python net/hop2_diag.py ...
    want = os.environ.get("VARIANTS", "A,B,C,D").split(",")
    ALL = [("A", "A 現況（含 sensor 當重建目標）", False, False, True),
           ("B", "B 只算有 peer 的節點（只有 motor）", True, False, True),
           ("C", "C = B，且 report_dev 從兩側都拿掉", True, True, True),
           # D 是 C 的關鍵對照：評分節點集合與 C 完全相同，只差在沒有訊息傳遞。
           # C vs D 才能回答「1.000 來自圖，還是光只評分 motor 就夠了」。
           ("D", "D = C，但拿掉訊息傳遞（無圖對照）", True, True, False)]
    res = {}
    for key, name, po, dd, ug in ALL:
        if key not in want:
            continue
        aucs, bgs, tops, diags, bases = [], [], [], [], []
        for sd in SEEDS:
            ne, gs, hp, rp, dg = run(d, tr, sd, po, dd, ug)
            diags.append(dg)
            thr = float(np.quantile(gs[tr], BUDGET))
            hit = gs > thr
            row = {}
            for s in SCENS + ["benign"]:
                m = te & (scen == s)
                mal, ben = m & (y == 1), m & (y == 0)
                row[s] = (float(average_precision_score(y[m], gs[m]))
                          if mal.sum() and ben.sum() else float("nan"),
                          float(hit[ben].mean()) if ben.sum() else float("nan"))
            aucs.append(row)
            # node-level top1（只在注入秒、候選=該秒有值的節點）
            gidn = d["graph_id"].numpy()
            # 基準只能在**真正可被選中**的節點上算：ne 已被 score_mask 歸零，
            # 所以 argmax 只可能挑中 score_mask>0 的節點（HOP=1 就是 motor）。
            # 拿「所有有值節點」當分母會把基準低估（0.167 vs 實際 0.25）。
            smk = dg.get("score_mask", np.ones(len(nodes)))
            t1, base = {}, {}
            for s in SCENS:
                sel = (nodes.scenario.values == s) & rep_np & \
                      np.array([te[g] and y[g] == 1 for g in gidn])
                hits = n = 0
                rnd = []          # 每一秒的候選數 → 隨機基準 = mean(1/候選數)
                for sec in np.unique(nodes.sec.values[sel]):
                    idx = np.where(sel & (nodes.sec.values == sec))[0]
                    if len(idx) == 0:
                        continue
                    n += 1
                    cnt = int((smk[idx] > 0).sum())
                    if cnt:
                        rnd.append(1.0 / cnt)
                    hits += nodes.node.values[idx[np.argmax(ne[idx])]] == ATTACKER
                t1[s] = hits / n if n else float("nan")
                # ⚠️ 隨機基準必須**從資料算**，不能寫死。HOP=1 把評分目標限定在
                # motor（3 台）→ 基準 ≈ 0.33；3s6m 的 2 跳版每秒約 9 個有值節點
                # → 0.11。用錯的基準會把「純隨機」的 D 讀成「有一點訊號」。
                base[s] = float(np.mean(rnd)) if rnd else float("nan")
            tops.append(t1); bases.append(base)
        res[name] = (aucs, tops, diags, bases)

    out("\n" + "=" * 78)
    out(f"結果（{len(SEEDS)} seeds，mean±std）")
    out("=" * 78)
    out("  PR-AUC（每個攻擊場景一欄）+ benign 背景率")
    out("  " + f"{'變體':<36}" + "".join(f"{s[:14]:>16}" for s in SCENS)
        + f"{'benign 背景率':>14}")
    for name, (aucs, _, _, _) in res.items():
        cells = ""
        for s in SCENS:
            v = [a[s][0] for a in aucs]
            cells += f"{np.mean(v):>10.3f}±{np.std(v):.3f}"
        b = [a["benign"][1] for a in aucs]
        out(f"  {name:<36}{cells}{np.mean(b):>11.1%}")
    out(f"\n  node-level top1（指認出 {ATTACKER} 的比例）")
    out("  " + f"{'變體':<36}" + "".join(f"{s[:14]:>16}" for s in SCENS))
    for name, (_, tops, _, _) in res.items():
        cells = ""
        for s in SCENS:
            v = [t[s] for t in tops]
            cells += f"{np.mean(v):>10.3f}±{np.std(v):.3f}"
        out(f"  {name:<36}{cells}")
    out("\n  對照：gnn_ablation 的 V1（=變體 A）comp PR-AUC 0.051 / V3（無圖）0.053")
    _b = next(iter(res.values()))[3]
    out("  隨機猜的 top1 基準（由資料算，= 每秒候選數的倒數平均）："
        + "  ".join(f"{s}={np.mean([x[s] for x in _b]):.3f}" for s in SCENS))

    # ---- HOP=1 的誠實性量測：模型到底學到了多少（見檔頭「責任切分」）----
    if HOP == 1:
        out("\n  ⭐ 誠實性量測：δ = ĝ − cand，也就是模型**學到**的修正量")
        out("  " + f"{'變體':<36}{'δ 中位':>12}{'δ p95':>12}{'δ p95 / v 的 sd':>18}")
        for name, (_, _, diags, _) in res.items():
            if not diags or "delta_med" not in diags[0]:
                continue
            md = np.mean([x["delta_med"] for x in diags])
            p95 = np.mean([x["delta_p95"] for x in diags])
            sd_ = np.mean([x["v_sd"] for x in diags])
            out(f"  {name:<36}{md:>12.5f}{p95:>12.5f}{p95/max(sd_,1e-9):>18.4f}")
        out("  解讀：δ ≈ 0 代表恆等解 ĝ = cand 已經最優（loss 從 epoch 0 就是 0、"
            "梯度為 0），")
        out("        亦即這條路徑的偵測力**不是學來的**，而是「圖結構決定了跟誰比」+"
            "「取 min」。")
        out("        這是預期行為，不是 bug —— 值一致性檢查天生是確定性的。報告時"
            "必須這樣寫，")
        out("        主張限於**拓撲韌性**（邊由當秒流量決定，不需要靜態 motor→"
            "sensor 對照表），")
        out("        不能寫成「GNN 學會了偵測冒用」。GNN 真正在學的部分是流量型攻擊，"
            "見 graph_clf.py。")

    # HOP=1 另存檔名，避免覆蓋既有 3s6m 的 2 跳結果。
    # ⚠️ RESULT_SUFFIX：跑煙霧測試（少 epochs / 單 seed）時**務必**設定它，
    # 否則 5 epochs 的垃圾數字會覆蓋掉正式結果檔 —— 2026-08-12 已經發生過一次，
    # 把既有的 2 跳正式結果蓋掉了（靠 hop2_diag_results_ABC.txt 才救回關鍵數字）。
    #   例： RESULT_SUFFIX=_smoke HOP=1 ml/venv/bin/python net/hop2_diag.py <dir>
    sfx = os.environ.get("RESULT_SUFFIX", "")
    fn = ("hop2_diag_results.txt" if HOP == 2
          else f"hop2_diag_results_hop{HOP}.txt")
    if sfx:
        fn = fn.replace(".txt", f"{sfx}.txt")
    with open(os.path.join(gdir, fn), "w", encoding="utf-8") as f:
        f.write("\n".join(log) + "\n")
    out(f"\n報告已存: {gdir}/{fn}")


if __name__ == "__main__":
    main()
