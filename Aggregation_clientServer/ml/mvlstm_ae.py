#!/usr/bin/env python3
# =============================================================================
# mvlstm_ae.py ── LSTM Autoencoder：對連續特徵做重建，以重建誤差門檻判定異常
# =============================================================================
# 定位（相對 mvdeeplog.py 的「一般 LSTM」）
# -----------------------------------------------------------------------------
# mvdeeplog.py 是**預測式** LSTM：吃 W 步、預測「下一步」的 (模板, dt, 值)，
#   異常分數 = 對真實下一步的 surprisal / NLL。它需要 benign 當「正確答案」來
#   比對，本質是 one-step forecasting。
#
# 本檔是**重建式** LSTM Autoencoder：只吃連續數值特徵的一段視窗，壓成 latent
#   再解回同一段視窗，異常分數 = 重建誤差（MSE）。門檻取純正常 val 集的高分位。
#   —— 只在 benign 上訓練，模型只學會重建「正常的數值節律與值」；攻擊注入的
#      反常間隔 / 反常距離值無法被低維 latent 還原 → 重建誤差爆高。
#
# 兩者用**完全相同的資料管線**（split_segments 分流、baseline/test 切分、seen-only、
# 逐秒聚合、正規化只由 train 估），所以報表可與 mvdeeplog_results*.txt 逐行對照，
# 回答「重建式 vs 預測式，哪個對數值異常更有效」。
#
# 連續特徵（三個「數值」通道 + 一個條件通道）
# -----------------------------------------------------------------------------
#   ch0  log1p(dt_source)  同來源到達間隔（間隔時間）
#   ch1  dt_stream         流內相鄰兩步間隔（節律 / 最接近「回應時間」的連續量；
#                          motor 流上它近似 sensor→motor 的回音節拍）
#   ch2  正規化 dist       距離值（值）
#   ch3  val_mask          該步有沒有距離值（0/1）—— **只當輸入條件，不計入誤差**
#   ⚠ 應用層 log 沒有真正的網路 response_time（那在 net/ 的 pcap 特徵裡）。
#     這裡用 dt_stream 當「時序/回應」通道的代理。
#
# 評分錨點：視窗 = 以某行結尾的 W 步；分數錨在**該視窗最後一行**（最能定位是哪一
#   行反常）。同時輸出 window-mean 版本供參考。
#
# 2026-08-23 修正三處會系統性壓低 AE 分數的實作缺陷（詳見各處 [修正N] 註解）
# -----------------------------------------------------------------------------
#  [修正1] ch2 缺值不再零填。topo3 有 34.6% 的行沒有 dist（Motor 50.2%、
#     System/App 100%），舊版填 0 後**連同假 0 一起估 mean/std**（16.76/15.72，
#     真值是 25.63/12.26），正規化後假 0 變成 −1.07、真值擠在 +0.56 附近 ——
#     ch2 實質退化成「這行有沒有值」的二元指示器。loss 雖有遮罩，但**輸入沒遮罩**，
#     encoder 還是吃得到。現在：mean/std 只由有效值估（nanmean/nanstd），缺值在
#     正規化後填 0（= 該通道均值），並把「有沒有值」拆成獨立的 ch3 條件通道。
#
#  [修正2] decoder 不再是純 repeat-vector。舊版把 latent 原封不動複製 W 份餵給
#     decoder，每一步的輸入完全相同 → decoder 沒有任何位置資訊，只能收斂到
#     「各位置的平均」，正常樣本的重建誤差被抬到自然變異的量級，異常的增量被淹掉。
#     現在在每步接上**可學的位置嵌入**，decoder 分得出自己在第幾步。
#     （刻意不用 teacher forcing：那會給 decoder 一條直接複製真值的捷徑，
#       在異常樣本上反而更容易重建，等於自廢武功。）
#
#  [修正3] 分數不再等權相加三通道。dt 通道的殘差變異遠大於 dist，等權相加後
#     總分幾乎等於 dt_source 分數（舊版總分 PR-AUC 0.266 ≈ dt_source 單通道 0.267）。
#     現在先用 **val（純正常）集的逐通道誤差 p90** 當尺度標準化，再合併；
#     同時輸出 sum 與 max 兩種合併方式。這也讓 Wva 真正被用到（舊版算完就沒用，
#     門檻其實是從測試集正常行取的，與註解宣稱的「val 集」不符）。
#
# 執行：
#   SCENARIO_FILTER=topo3 ml/venv/bin/python ml/mvlstm_ae.py
#   EPOCHS=15 HIDDEN=64 ml/venv/bin/python ml/mvlstm_ae.py
# 輸出： ml/out/mvlstm_ae_results.txt   （RESULT_SUFFIX 可加後綴避免互蓋）
# =============================================================================
import os
import sys
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import average_precision_score, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "out")

# 沿用 mvdeeplog / ngram_detector 的分流與切分口徑，確保與既有報告逐行可比
from ngram_detector import split_segments, VAL_FRAC, SOURCE_COL   # noqa: E402

SCENARIO_FILTER = os.environ.get("SCENARIO_FILTER", "").strip()
RESULT_SUFFIX   = os.environ.get("RESULT_SUFFIX", "").strip()
STREAM_MODE     = os.environ.get("STREAM_KEY", "pair").strip()

# 窗長對齊 mvdeeplog 的 10，方便逐行對照。latent 刻意壓到遠小於 W×3 個輸入值，
# 逼模型學「正常」的低維流形，攻擊才還原不出來。
WINDOW = int(os.environ.get("WINDOW", "10"))
HIDDEN = int(os.environ.get("HIDDEN", "64"))
LATENT = int(os.environ.get("LATENT", "16"))
LAYERS = int(os.environ.get("LAYERS", "1"))
EPOCHS = int(os.environ.get("EPOCHS", "15"))
BATCH  = int(os.environ.get("BATCH", "128"))
LR     = float(os.environ.get("LR", "1e-3"))
POSD   = int(os.environ.get("POSD", "16"))    # [修正2] decoder 位置嵌入維度
# [修正3] 消融開關：SCORE_NORM=0 → 三通道等權相加（舊行為），用來隔離標準化的影響
SCORE_NORM = os.environ.get("SCORE_NORM", "1") != "0"
SEED   = 42

# ch3 是條件通道（告訴 encoder「這步沒有距離值」），不參與重建誤差
NCH      = 4
CH_NAMES = ["dt_source", "dt_stream", "dist", "val_mask"]
SCORE_CH = [0, 1, 2]                          # 真正計入分數的通道

# 小型 LSTM 上把 intra-op 執行緒開滿反而爭用拖慢；設小值（可用 TORCH_THREADS 覆蓋）
torch.set_num_threads(int(os.environ.get("TORCH_THREADS", "4")))
log = []
def emit(s=""):
    print(s, flush=True); log.append(str(s))   # flush：否則進度被 stdout buffer 吃掉


# ---------------------------------------------------------------------------
# 1. 特徵：把一條 segment 切成滑動視窗的連續特徵張量
# ---------------------------------------------------------------------------
def segment_arrays(sub):
    """回傳 (連續特徵矩陣 [n,4], val 遮罩 [n], DataFrame 索引)。

    [修正1] ch0~ch2 的缺值一律保留成 NaN，讓正規化常數用 nanmean/nanstd 估；
    填值延後到「正規化之後」才做（填 0 = 該通道均值），避免假值汙染分佈。
    """
    idx = sub.index.values
    dt = sub["dt_source"].values.astype(np.float64)
    dt_log = np.where(np.isfinite(dt), np.log1p(np.clip(dt, 0, None)), np.nan)

    ts = pd.to_datetime(sub["ts"], errors="coerce").astype("int64").values / 1e9
    d_stream = np.full(len(sub), np.nan)       # 每條 segment 第一步沒有前一步 → NaN
    if len(sub) > 1:
        d_stream[1:] = np.log1p(np.clip(np.diff(ts), 0, None))

    val = sub["dist"].values.astype(np.float64)
    val_ok = np.isfinite(val)
    val = np.where(val_ok, val, np.nan)

    feat = np.stack([dt_log, d_stream, val, val_ok.astype(np.float64)], axis=1)
    return feat, val_ok.astype(np.float32), idx


def make_windows(feat, vmask, idx, window=WINDOW):
    """滑動視窗。每個視窗錨在**最後一行**（POS = idx[i+window-1]）。"""
    n = len(idx)
    if n < window:
        return None
    X, MV, POS = [], [], []
    for i in range(n - window + 1):
        j = i + window
        X.append(feat[i:j])
        MV.append(vmask[i:j])
        POS.append(idx[j - 1])
    return (np.array(X, dtype=np.float32),
            np.array(MV, dtype=np.float32),
            np.array(POS))


def segments_to_windows(df, segs, norm):
    """segs → 串起來的視窗集合，套用 train 估的正規化常數。"""
    mu, sd = norm
    packs = []
    for _, idx in segs:
        sub = df.loc[idx]
        feat, vmask, ix = segment_arrays(sub)
        feat = (feat - mu) / sd
        feat = np.nan_to_num(feat, nan=0.0)    # [修正1] 正規化後才填，0 即均值
        w = make_windows(feat, vmask, np.asarray(ix))
        if w is not None:
            packs.append(w)
    if not packs:
        return None
    return tuple(np.concatenate([p[k] for p in packs]) for k in range(3))


# ---------------------------------------------------------------------------
# 2. 模型：seq2seq LSTM Autoencoder
# ---------------------------------------------------------------------------
class LSTMAE(nn.Module):
    def __init__(self, n_ch=NCH, hidden=HIDDEN, latent=LATENT, layers=LAYERS,
                 window=WINDOW, posd=POSD):
        super().__init__()
        self.window = window
        self.enc = nn.LSTM(n_ch, hidden, layers, batch_first=True)
        self.to_latent = nn.Linear(hidden, latent)
        self.from_latent = nn.Linear(latent, hidden)
        self.pos = nn.Embedding(window, posd)          # [修正2] 每步的位置嵌入
        self.dec = nn.LSTM(hidden + posd, hidden, layers, batch_first=True)
        self.out = nn.Linear(hidden, n_ch)

    def forward(self, x):
        o, _ = self.enc(x)
        z = self.to_latent(o[:, -1, :])                # bottleneck：整窗壓成 latent
        h0 = torch.relu(self.from_latent(z))
        seq = h0.unsqueeze(1).repeat(1, self.window, 1)
        # [修正2] 接上位置嵌入，decoder 才分得出自己在重建第幾步，
        #         不會退化成「輸出各位置的平均」
        p = self.pos.weight.unsqueeze(0).expand(x.size(0), -1, -1)
        d, _ = self.dec(torch.cat([seq, p], dim=2))
        return self.out(d)                             # 重建的 [B, W, n_ch]


# ---------------------------------------------------------------------------
# 3. 訓練
# ---------------------------------------------------------------------------
def recon_err(recon, x, mv):
    """逐步、逐通道的平方誤差與權重。ch2 用遮罩；ch3 是條件通道，權重恆 0。"""
    se = (recon - x) ** 2                          # [B, W, 4]
    w = torch.ones_like(se)
    w[:, :, 2] = mv                                # ch2 只在有距離值時計入
    w[:, :, 3] = 0.0                               # ch3 只當輸入，不計入誤差
    return se, w


def train(model, W):
    torch.manual_seed(SEED); np.random.seed(SEED)
    X, MV, _ = W
    ds = TensorDataset(torch.tensor(X), torch.tensor(MV))
    dl = DataLoader(ds, batch_size=BATCH, shuffle=True)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    model.train()
    for ep in range(EPOCHS):
        tot = 0.0
        for xb, mvb in dl:
            opt.zero_grad()
            recon = model(xb)
            se, w = recon_err(recon, xb, mvb)
            loss = (se * w).sum() / w.sum().clamp_min(1.0)
            loss.backward(); opt.step()
            tot += float(loss.detach()) * len(xb)
        emit(f"    epoch {ep+1:2d}/{EPOCHS}  recon_loss={tot/len(ds):.5f}")
    return model


@torch.no_grad()
def score_raw(model, W):
    """回傳逐通道的原始平方誤差與權重（last-step 與 window-mean 各一份）。

    合併成單一分數的動作留到 combine()，因為尺度要由 val 集決定（[修正3]）。
    """
    X, MV, _ = W
    model.eval()
    sl_se, sl_w, sw_se, sw_w = [], [], [], []
    for i in range(0, len(X), 4096):
        sl = slice(i, i + 4096)
        xb = torch.tensor(X[sl]); mvb = torch.tensor(MV[sl])
        se, w = recon_err(model(xb), xb, mvb)          # [b, W, 4]
        sl_se.append(se[:, -1, :].numpy()); sl_w.append(w[:, -1, :].numpy())
        # window-mean：整窗有效誤差在時間軸上先平均，通道維留著等標準化
        sw_se.append(((se * w).sum(dim=1) / w.sum(dim=1).clamp_min(1e-9)).numpy())
        sw_w.append((w.sum(dim=1) > 0).float().numpy())
    return (np.concatenate(sl_se), np.concatenate(sl_w),
            np.concatenate(sw_se), np.concatenate(sw_w))


def channel_scale(se, w):
    """[修正3] 由 val（純正常）集估每個通道的誤差尺度：有效步的 p90。"""
    sc = np.ones(NCH, dtype=np.float64)
    if not SCORE_NORM:
        return sc                                  # 消融：退回等權相加
    for k in SCORE_CH:
        v = se[:, k][w[:, k] > 0]
        if len(v):
            sc[k] = max(float(np.percentile(v, 90)), 1e-12)
    return sc


def combine(se, w, scale):
    """逐通道先除以 val 尺度，再合併。回傳 (加權平均版, max 版)。"""
    z = np.where(w > 0, se / scale, 0.0)[:, SCORE_CH]
    ww = w[:, SCORE_CH]
    mean = (z * ww).sum(1) / np.clip(ww.sum(1), 1e-9, None)
    mx = np.where(ww > 0, z, -np.inf).max(1)
    return mean, np.where(np.isfinite(mx), mx, 0.0)


# ---------------------------------------------------------------------------
# 4. 主流程
# ---------------------------------------------------------------------------
def report_block(tag_prefix, y, typ, s, seen, thr_val=None):
    """列印 全量 / seen-only 的 PR-AUC、ROC-AUC、逐類命中。

    門檻兩種都印：val p99.9（[修正3] 才是真正沒偷看測試集的那個）以及
    測試集正常行 p99.9（舊報表用的口徑，留著方便逐行對照）。
    """
    for tag, m in [("全量", np.ones(len(y), bool)), ("seen-only", seen)]:
        yy, ss, tt = y[m], s[m], typ[m]
        if yy.sum() == 0 or (yy == 0).sum() == 0:
            continue
        emit(f"  ({tag_prefix} · {tag}) PR-AUC={average_precision_score(yy, ss):.3f}"
             f"  ROC-AUC={roc_auc_score(yy, ss):.3f}")
        thrs = [("測試正常 p99.9", np.percentile(ss[yy == 0], 99.9))]
        if thr_val is not None:
            thrs.insert(0, ("val p99.9", thr_val))
        for tname, thr in thrs:
            per = "  ".join(f"[{a}] {int(((ss >= thr) & (tt == a)).sum())}/{int((tt == a).sum())}"
                            for a in ["S", "T", "R", "RP"] if (tt == a).sum())
            fp = int(((ss >= thr) & (yy == 0)).sum())
            emit(f"           thr={tname:<14} 逐類命中: {per}   誤報 {fp}/{int((yy==0).sum())}")


def main():
    emit("讀取 parsed_all.csv …")
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    if SCENARIO_FILTER:
        df = df[df.scenario.str.contains(SCENARIO_FILTER, na=False)]
    emit(f"讀入 {len(df)} 行（filter={SCENARIO_FILTER or '無'}）")
    df = df.sort_values(["scenario", "seq_pos"]).reset_index(drop=True)
    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].unique()))}
    df["tid"] = df["template_id"].map(vocab)          # split_segments 需要 tid 欄

    scen = list(df.scenario.unique())
    base_scen = [s for s in scen if "baseline" in s]
    test_scen = [s for s in scen if "baseline" not in s]
    if not base_scen or not test_scen:
        emit("缺 baseline 或測試場景"); return

    emit("=" * 74)
    emit("LSTM Autoencoder —— 重建連續特徵 (dt_source, dt_stream, dist)，重建誤差判定")
    emit("=" * 74)
    emit(f"窗長={WINDOW}  hidden={HIDDEN}  latent={LATENT}  layers={LAYERS}  "
         f"epochs={EPOCHS}  posd={POSD}  分流 STREAM_KEY={STREAM_MODE}（{SOURCE_COL}）")
    emit(f"訓練場景 {len(base_scen)} 個 / 測試場景 {len(test_scen)} 個")

    # baseline 時序切 train/val，再各自分流（與 mvdeeplog 同口徑）
    tr_segs, va_segs = [], []
    for s in base_scen:
        sub = df[df.scenario == s]
        cut = int(len(sub) * (1 - VAL_FRAC))
        tr_segs += split_segments(sub.iloc[:cut], STREAM_MODE)
        va_segs += split_segments(sub.iloc[cut:], STREAM_MODE)
    te_segs = [sg for s in test_scen
               for sg in split_segments(df[df.scenario == s], STREAM_MODE)]

    # 正規化常數只由 train 估，不可偷看 val/test。
    # [修正1] 用 nanmean/nanstd，缺值不參與；ch3 是 0/1 條件通道，不正規化。
    tr_idx = np.concatenate([i for _, i in tr_segs])
    feats_tr = []
    for _, idx in tr_segs:
        f, _, _ = segment_arrays(df.loc[idx])
        feats_tr.append(f)
    allf = np.concatenate(feats_tr)
    mu = np.nanmean(allf, axis=0); sd = np.nanstd(allf, axis=0) + 1e-9
    mu[3], sd[3] = 0.0, 1.0
    norm = (mu.astype(np.float32), sd.astype(np.float32))
    emit(f"通道正規化(僅由 train 的**有效值**估) mean={np.round(mu,3).tolist()} "
         f"std={np.round(sd,3).tolist()}")
    emit(f"  ch2 缺值率 = {float(np.isnan(allf[:,2]).mean()):.3f}"
         f"（舊版把這些填 0 後一起估 mean/std，導致 ch2 退化成有無值的指示器）")

    Wtr = segments_to_windows(df, tr_segs, norm)
    Wva = segments_to_windows(df, va_segs, norm)
    Wte = segments_to_windows(df, te_segs, norm)
    if Wtr is None or Wva is None or Wte is None:
        emit("視窗不足"); return
    emit(f"訓練視窗 {len(Wtr[0])}   val 視窗 {len(Wva[0])}   測試視窗 {len(Wte[0])}")

    pos = Wte[2]
    y = df.loc[pos, "label"].values.astype(int)
    typ = df.loc[pos, "attack_type"].values
    seen = df.loc[pos, "tid"].isin(set(np.unique(df.loc[tr_idx, "tid"]))).values
    sec = (df.loc[pos, "scenario"].astype(str) + "|" + df.loc[pos, "ts_sec"].astype(str)).values
    emit(f"評估位置 {len(pos)} 行，異常 {int(y.sum())}"
         f"（{dict(pd.Series(typ[y == 1]).value_counts())}）")

    emit("\n" + "-" * 74)
    emit("訓練 LSTM-AE（只餵 benign 視窗）")
    emit("-" * 74)
    torch.manual_seed(SEED); np.random.seed(SEED)
    model = LSTMAE()
    train(model, Wtr)

    # [修正3] 先在 val（純正常）上量出逐通道誤差尺度與門檻，測試才沿用
    va_sl_se, va_sl_w, va_sw_se, va_sw_w = score_raw(model, Wva)
    scale = channel_scale(va_sl_se, va_sl_w)
    emit(f"\nval 集逐通道誤差尺度 p90（[修正3] 標準化用）: "
         + "  ".join(f"{CH_NAMES[k]}={scale[k]:.4f}" for k in SCORE_CH))
    va_last, va_max = combine(va_sl_se, va_sl_w, scale)
    va_win, _ = combine(va_sw_se, va_sw_w, scale)
    thr_last = float(np.percentile(va_last, 99.9))
    thr_max = float(np.percentile(va_max, 99.9))
    thr_win = float(np.percentile(va_win, 99.9))

    te_sl_se, te_sl_w, te_sw_se, te_sw_w = score_raw(model, Wte)
    s_last, s_max = combine(te_sl_se, te_sl_w, scale)
    s_win, _ = combine(te_sw_se, te_sw_w, scale)

    if os.environ.get("DUMP_SCORES"):
        pd.DataFrame({
            "scenario": df.loc[pos, "scenario"].values,
            "ts_sec": df.loc[pos, "ts_sec"].values,
            "label": y, "attack_type": typ, "score": s_last, "score_max": s_max,
        }).to_csv(os.path.join(OUT, f"mvlstm_ae_scores{RESULT_SUFFIX}.csv"), index=False)
        # val（純正常、訓練期未使用）分數：供 second_level_eval 以 val 校準門檻
        vpos = Wva[2]
        pd.DataFrame({
            "scenario": df.loc[vpos, "scenario"].values,
            "ts_sec": df.loc[vpos, "ts_sec"].values,
            "score": va_last, "score_max": va_max,
        }).to_csv(os.path.join(OUT, f"mvlstm_ae_valscores{RESULT_SUFFIX}.csv"), index=False)

    emit("\n" + "-" * 74)
    emit("偵測結果（重建誤差為分數；逐通道先用 val p90 標準化再合併）")
    emit("-" * 74)
    report_block("last-step", y, typ, s_last, seen, thr_last)
    report_block("last-step·max", y, typ, s_max, seen, thr_max)
    report_block("window-mean", y, typ, s_win, seen, thr_win)

    # 逐秒聚合（與 mvdeeplog 同）
    for nm, sc in [("last-step", s_last), ("last-step·max", s_max)]:
        d = pd.DataFrame({"sec": sec, "s": sc, "y": y}).groupby("sec").agg(
            s=("s", "max"), y=("y", "max"))
        emit(f"\n  (逐秒 · {nm}) PR-AUC={average_precision_score(d.y, d.s):.3f}"
             f"   秒數={len(d)} 異常秒={int(d.y.sum())}")

    # 逐通道鑑別力：看是 dt 還是 val 在驅動偵測（對照 mvdeeplog 診斷 b）
    # ⚠ 只在該通道**有效**的行上評估。ch2 對沒有距離值的行沒有意義，若照舊把它們
    #   當成 se=(recon−填充值)² 一起排名，等於在量「這行有沒有距離值」——那正是
    #   RESULTS_SUMMARY.md 記載的「管道 2」parser 假訊號，會把 R 幾乎全部誤判成偵測到。
    emit("\n  各通道**單獨**的重建誤差鑑別力（last-step，僅該通道有效的行）")
    emit(f"    {'通道':<12}{'PR-AUC':>9}{'ROC-AUC':>10}{'涵蓋':>8}   逐類命中 @ val p99.9")
    for k in SCORE_CH:
        ok = te_sl_w[:, k] > 0
        x, yy, tt = te_sl_se[ok, k], y[ok], typ[ok]
        if len(np.unique(x)) < 2 or yy.sum() == 0:
            continue
        thr = float(np.percentile(va_sl_se[:, k][va_sl_w[:, k] > 0], 99.9))
        per = "  ".join(f"[{a}] {int(((x >= thr) & (tt == a)).sum())}/{int((tt == a).sum())}"
                        for a in ["S", "T", "R", "RP"] if (tt == a).sum())
        emit(f"    {CH_NAMES[k]:<12}{average_precision_score(yy, x):>9.3f}"
             f"{roc_auc_score(yy, x):>10.3f}{ok.mean():>8.2f}   {per}")

    # 只看 T/RP：R 是已證實的模板洩漏（見 RESULTS_SUMMARY.md 消融），S 有注入洩漏
    m = ~np.isin(typ, ["R", "S"])
    emit(f"\n  只計 T/RP（排除已知洩漏的 R、S）  異常 {int(y[m].sum())}"
         f"   PR-AUC={average_precision_score(y[m], s_last[m]):.3f}"
         f"   ROC-AUC={roc_auc_score(y[m], s_last[m]):.3f}")

    emit("\n" + "=" * 74)
    emit("解讀：AE 只學會重建 benign 的數值節律與值。攻擊注入的反常間隔(dt)或")
    emit("反常/對不上的距離值(dist)無法被低維 latent 還原 → 重建誤差爆高。")
    emit("與 mvdeeplog（預測式 LSTM）對照：兩者資料/分流/切分一致，可直接比 PR-AUC。")

    p = os.path.join(OUT, f"mvlstm_ae_results{RESULT_SUFFIX}.txt")
    open(p, "w", encoding="utf-8").write("\n".join(log) + "\n")
    print(f"\n報告已存: {p}")


if __name__ == "__main__":
    main()
