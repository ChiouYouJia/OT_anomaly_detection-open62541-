#!/usr/bin/env python3
# =============================================================================
# mvdeeplog.py ── 多變量序列模型：不只預測「下一個模板」，也預測「下一步的時間與值」
# =============================================================================
# 動機（為什麼現有的 DeepLog 對 S 是 0%）
# -----------------------------------------------------------------------------
# 現行 deeplog.py 的形狀是：
#     輸入 = 模板 ID 序列  →  預測 = 下一個模板  →  分數 = 實際模板的 surprisal
# S（欺騙）偽造的 sensor 讀數，用的是**與 38713 行正常讀數完全相同的模板**，
# 前後文也是 benign 最常見的轉移。也就是說 S 在「模板」這個觀測維度上不存在。
# 實測 bigram 與 DeepLog 對 S 的 seen-only recall 分別是 0% 與 36%（後者靠 top-k
# 邊界雜訊撿到的）。換更大的模型不會有幫助 —— 這是輸入表示的問題，不是容量問題。
#
# 關鍵設計決定：**光把 Δt/值加進「輸入」是不夠的，預測目標也要一起換。**
#   若輸出仍然只有模板，S 依舊不可見（它沒改變模板）。異常必須出現在預測目標裡。
#   所以本模型有三個頭，逐步預測下一步的 (模板, 同源間隔, 距離值)：
#
#       輸入 x_{t-W..t} ──→ LSTM ──┬─→ head_tmpl : softmax over V   → CE
#                                  ├─→ head_dt   : (μ, log σ)       → Gaussian NLL
#                                  └─→ head_val  : (μ, log σ)       → Gaussian NLL（遮罩）
#
#       異常分數 = 三個 NLL 各自用 val（純正常）標準化後加權相加
#
# 模型會自己學到的東西（不需要寫成規則）
# -----------------------------------------------------------------------------
#   · 節律 → head_dt：benign 的 sensor dt_source 是 1.002±0.005（p1 0.991/p99 1.005），
#     模型學到極小的 σ。S 是隨機相位注入（median 0.547）、RP 帶著原始內嵌時間戳
#     （median 0.000），兩者都會在這一維上爆出巨大 NLL。
#   · 回音 → head_val：**依 pair 分流後**，motor 的距離值等於同流前一筆 sensor 的值，
#     實測 median 誤差 0.000000、p99 0.000000（n=38586，純 baseline）。模型能學到
#     σ≈0。攻擊者注入假值 X 但真 sensor 送的是 Y、motor 回報 Y → 預測 X 實際 Y → 大 NLL。
#     這是 sensor_no_echo 規則的模型版本，而且是模型自己學的。
#
# 輸入刻意**只放原始觀測**，不放衍生的偵測特徵
# -----------------------------------------------------------------------------
#   排除 sensor_no_echo / dist_ts_occurrence / sensor_win_count /
#   sensor_motor_mismatch —— 那些是規則的答案，放進去就只是「規則換一種寫法」。
#   （sensor_no_echo 還用到未來 5 秒的資訊，是 lookahead。）
#   也**不放 pair 編號**：那是身分不是行為，放了模型會記住「哪個 pair 常被打」，
#   而且拓樸從 3 組擴到 6 組時就得重訓。role（Sensor/Motor）是拓樸無關的，可以放。
#
# ⚠ pair 分流是本設計的**架構前提**，不是可調選項
# -----------------------------------------------------------------------------
#   實測（純 baseline，motor 值能否由同流前一筆 sensor 值預測）：
#       不分流（三 pair 交錯）  median 誤差 6.098   可預測率 34.8%
#       依 pair 分流            median 誤差 0.000   可預測率 99.8%
#   不分流的話「前一筆 sensor 值」來自隨機哪個 pair，那個關係根本不存在，
#   head_val 只會學到很大的 σ 而完全失效。
#
# 可證偽的預測（先寫下來，跑完對照）
# -----------------------------------------------------------------------------
#   加上 head_dt 之後，S 必須從 0% 明顯上升、RP 必須接近 100%。
#   如果沒有，這個設計就是錯的，不必再往下加 head_val。
#
# 執行：
#   SCENARIO_FILTER=topo3 ml/venv/bin/python ml/mvdeeplog.py
#   MODES=tmpl,tmpl+dt ml/venv/bin/python ml/mvdeeplog.py   # 只跑指定消融
# 輸出： ml/out/mvdeeplog_results.txt
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

# 分流/切分邏輯直接沿用 ngram_detector，確保與既有報告逐行可比
from ngram_detector import split_segments, VAL_FRAC, WARMUP, SOURCE_COL   # noqa: E402

SCENARIO_FILTER = os.environ.get("SCENARIO_FILTER", "").strip()
RESULT_SUFFIX   = os.environ.get("RESULT_SUFFIX", "").strip()
STREAM_MODE     = os.environ.get("STREAM_KEY", "pair").strip()
MODES = [m.strip() for m in
         os.environ.get("MODES", "tmpl,tmpl+dt,tmpl+dt+val").split(",") if m.strip()]

# 窗長對齊現有 deeplog.py / compare_ngram_deeplog.py 的 10，兩個理由：
#   (1) 數字才能與既有報告逐行對照；
#   (2) 窗長越大，每條流開頭被跳過的行越多 —— 用 16 時 RP 的評估樣本從 54 掉到 25，
#       那個類別的結論會變得不可靠。
WINDOW, HIDDEN, LAYERS, EPOCHS, BATCH, LR = 10, 64, 2, 15, 128, 1e-3
SEED = 42
# 運作點：逐類命中所用之「正常誤報」百分位。預設 99.9（≈0.1% FPR），
# 可用 OP_PCTL 環境變數改（例如 99.5 ≈ 0.5% FPR）。不影響 PR/ROC-AUC。
OP_PCTL = float(os.environ.get("OP_PCTL", "99.9"))
LOGSIG_MIN, LOGSIG_MAX = -6.0, 3.0     # 夾住 log σ，避免 σ→0 讓 NLL 爆掉
ROLES = ["Sensor", "Motor", "System", "App"]

log = []
def emit(s=""):
    print(s); log.append(str(s))


# ---------------------------------------------------------------------------
# 1. 特徵
# ---------------------------------------------------------------------------
def build_features(df):
    """回傳逐行的 (tid, role_id, 數值特徵矩陣, 目標 dt, 目標 val, val 遮罩)。

    數值特徵刻意只有兩維原始觀測：
      · log1p(dt_source) —— 同來源到達間隔（NaN → 0，另給遮罩位）
      · 正規化 dist      —— 距離值（NaN → 0，另給遮罩位）
    dt_stream（流內間隔）在 segment 切好之後才算得出來，於 make_windows 內補上。
    """
    tid = df["tid"].values.astype(np.int64)
    role = df["role"].map({r: i for i, r in enumerate(ROLES)}).fillna(3).values.astype(np.int64)

    dt = df["dt_source"].values.astype(np.float64)
    dt_ok = np.isfinite(dt)
    dt_log = np.where(dt_ok, np.log1p(np.clip(dt, 0, None)), 0.0)

    val = df["dist"].values.astype(np.float64)
    val_ok = np.isfinite(val)
    return tid, role, dt_log, dt_ok, val, val_ok


def gaussian_nll(x, mu, logsig):
    """逐元素高斯負對數似然（省略常數項）。"""
    logsig = torch.clamp(logsig, LOGSIG_MIN, LOGSIG_MAX)
    return logsig + 0.5 * ((x - mu) / torch.exp(logsig)) ** 2


# ---------------------------------------------------------------------------
# 2. 模型
# ---------------------------------------------------------------------------
class MVDeepLog(nn.Module):
    def __init__(self, V, n_num, hidden=HIDDEN, layers=LAYERS):
        super().__init__()
        self.emb_t = nn.Embedding(V, 32)
        self.emb_r = nn.Embedding(len(ROLES), 8)
        self.proj = nn.Linear(n_num, 24)
        self.lstm = nn.LSTM(32 + 8 + 24, hidden, layers, batch_first=True)
        self.head_tmpl = nn.Linear(hidden, V)
        self.head_dt = nn.Linear(hidden, 2)
        self.head_val = nn.Linear(hidden, 2)

    def forward(self, t, r, n):
        x = torch.cat([self.emb_t(t), self.emb_r(r), self.proj(n)], dim=-1)
        o, _ = self.lstm(x)
        h = o[:, -1, :]
        dt = self.head_dt(h)
        val = self.head_val(h)
        return self.head_tmpl(h), dt[:, 0], dt[:, 1], val[:, 0], val[:, 1]


# ---------------------------------------------------------------------------
# 3. 視窗
# ---------------------------------------------------------------------------
def make_windows(idx, feats, window=WINDOW):
    """把一條 segment（已是同一條流、依 seq_pos 排序）切成滑動視窗。

    dt_stream 在這裡算：流內相鄰兩步的 log1p 間隔。因為「流」的定義在
    split_segments 手上，parse_logs 不該預先算這一維。
    """
    tid, role, dt_log, dt_ok, val, val_ok, ts = feats
    n = len(idx)
    if n <= window:
        return None
    d_stream = np.zeros(n)
    gap = np.diff(ts)
    d_stream[1:] = np.log1p(np.clip(gap, 0, None))

    num = np.stack([dt_log, dt_ok.astype(float), val, val_ok.astype(float), d_stream], axis=1)
    X_t, X_r, X_n, Y_t, Y_dt, Y_v, M_v, POS = [], [], [], [], [], [], [], []
    for i in range(n - window):
        j = i + window
        X_t.append(tid[i:j]); X_r.append(role[i:j]); X_n.append(num[i:j])
        Y_t.append(tid[j]); Y_dt.append(dt_log[j])
        Y_v.append(val[j]); M_v.append(val_ok[j]); POS.append(idx[j])
    return (np.array(X_t), np.array(X_r), np.array(X_n, dtype=np.float32),
            np.array(Y_t), np.array(Y_dt, dtype=np.float32),
            np.array(Y_v, dtype=np.float32), np.array(M_v), np.array(POS))


def segments_to_windows(df, segs, norm=None):
    """segs = [(tid陣列, index陣列), ...] → 串起來的視窗集合。"""
    packs = []
    for _, idx in segs:
        sub = df.loc[idx]
        tid, role, dt_log, dt_ok, val, val_ok = build_features(sub)
        if norm is not None:
            mu, sd = norm
            val = np.where(val_ok, (val - mu) / sd, 0.0)
        else:
            val = np.where(val_ok, val, 0.0)
        ts = pd.to_datetime(sub["ts"], errors="coerce").astype("int64").values / 1e9
        w = make_windows(np.asarray(idx), (tid, role, dt_log, dt_ok, val, val_ok, ts))
        if w is not None:
            packs.append(w)
    if not packs:
        return None
    return tuple(np.concatenate([p[k] for p in packs]) for k in range(8))


# ---------------------------------------------------------------------------
# 4. 訓練與評分
# ---------------------------------------------------------------------------
def train(model, W, mode, epochs=EPOCHS):
    torch.manual_seed(SEED); np.random.seed(SEED)
    Xt, Xr, Xn, Yt, Ydt, Yv, Mv, _ = W
    ds = TensorDataset(torch.tensor(Xt), torch.tensor(Xr), torch.tensor(Xn),
                       torch.tensor(Yt), torch.tensor(Ydt),
                       torch.tensor(Yv), torch.tensor(Mv.astype(np.float32)))
    dl = DataLoader(ds, batch_size=BATCH, shuffle=True)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    ce = nn.CrossEntropyLoss()
    use_dt = "dt" in mode
    use_val = "val" in mode
    model.train()
    for ep in range(epochs):
        tot = 0.0
        for xt, xr, xn, yt, ydt, yv, mv in dl:
            opt.zero_grad()
            lt, mu_d, ls_d, mu_v, ls_v = model(xt, xr, xn)
            loss = ce(lt, yt)
            if use_dt:
                loss = loss + gaussian_nll(ydt, mu_d, ls_d).mean()
            if use_val and mv.sum() > 0:
                loss = loss + (gaussian_nll(yv, mu_v, ls_v) * mv).sum() / mv.sum()
            loss.backward(); opt.step()
            tot += float(loss.detach()) * len(xt)
        emit(f"    epoch {ep+1:2d}/{epochs}  loss={tot/len(ds):.4f}")
    return model


@torch.no_grad()
def score(model, W, mode):
    """回傳 (各分量分數 dict, 預測參數 dict)。分量都是逐步 NLL。"""
    Xt, Xr, Xn, Yt, Ydt, Yv, Mv, POS = W
    model.eval()
    outs = {"tmpl": [], "dt": [], "val": []}
    pred = {"mu_dt": [], "sig_dt": [], "mu_val": [], "sig_val": []}
    lsm = nn.LogSoftmax(dim=1)
    for i in range(0, len(Xt), 4096):
        sl = slice(i, i + 4096)
        lt, mu_d, ls_d, mu_v, ls_v = model(
            torch.tensor(Xt[sl]), torch.tensor(Xr[sl]), torch.tensor(Xn[sl]))
        yt = torch.tensor(Yt[sl])
        outs["tmpl"].append((-lsm(lt).gather(1, yt[:, None]).squeeze(1)).numpy())
        outs["dt"].append(gaussian_nll(torch.tensor(Ydt[sl]), mu_d, ls_d).numpy())
        v = gaussian_nll(torch.tensor(Yv[sl]), mu_v, ls_v).numpy()
        outs["val"].append(np.where(Mv[sl], v, np.nan))
        pred["mu_dt"].append(mu_d.numpy())
        pred["sig_dt"].append(torch.exp(torch.clamp(ls_d, LOGSIG_MIN, LOGSIG_MAX)).numpy())
        pred["mu_val"].append(mu_v.numpy())
        pred["sig_val"].append(torch.exp(torch.clamp(ls_v, LOGSIG_MIN, LOGSIG_MAX)).numpy())
    comp = {k: np.concatenate(v) for k, v in outs.items()}
    par = {k: np.concatenate(v) for k, v in pred.items()}
    return comp, par


def diagnose(df, W, comp, par, y, typ, mode):
    """診斷：模型到底有沒有學到節律？各分量單獨的鑑別力如何？

    這是 tmpl+dt 沒有讓 S 明顯上升時的第一個檢查點 —— 用來區分
    「設計錯」與「只是加權錯」：
      · 若 benign 的 sensor 步 σ 已經很小（≈ 實測的 0.005），代表節律學到了，
        問題出在把三個分量相加的方式 → 改權重/改聚合就能救。
      · 若 σ 是寬的，代表模型根本沒學到那個結構 → 特徵/架構要重來。
    """
    pos = W[7]
    role = df.loc[pos, "role"].values
    Ydt = W[4]
    emit("\n  診斷 (a) head_dt 學到的節律 —— 依角色分開看（單位：log1p 秒）")
    emit(f"    {'角色':<8}{'n':>7}{'實際 dt 中位':>13}{'預測 μ 中位':>13}"
         f"{'預測 σ 中位':>13}{'σ 的 p90':>11}")
    for r in ["Sensor", "Motor"]:
        m = (role == r) & (y == 0)
        if not m.sum():
            continue
        emit(f"    {r:<8}{int(m.sum()):>7}{np.median(Ydt[m]):>13.4f}"
             f"{np.median(par['mu_dt'][m]):>13.4f}"
             f"{np.median(par['sig_dt'][m]):>13.5f}"
             f"{np.percentile(par['sig_dt'][m], 90):>11.5f}")
    emit("    （benign 的 sensor dt_source 實測是 1.002±0.005 秒，")
    emit("      取 log1p 後 ≈ 0.694±0.0025 —— σ 應該落在這個量級才算學到）")

    emit("\n  診斷 (b) 各分量**單獨**的鑑別力（seen-only 不套用，直接看全量）")
    emit(f"    {'分量':<8}{'PR-AUC':>9}{'ROC-AUC':>10}   逐類命中 @ 正常 p99.9")
    for k in ["tmpl", "dt", "val"]:
        if (k == "dt" and "dt" not in mode) or (k == "val" and "val" not in mode):
            continue
        x = np.nan_to_num(comp[k], nan=0.0)
        if len(np.unique(x)) < 2:
            continue
        thr = np.percentile(x[y == 0], 99.9)
        per = "  ".join(f"[{a}] {int(((x >= thr) & (typ == a)).sum())}/{int((typ == a).sum())}"
                        for a in ["S", "T", "R", "RP"] if (typ == a).sum())
        emit(f"    {k:<8}{average_precision_score(y, x):>9.3f}"
             f"{roc_auc_score(y, x):>10.3f}   {per}")

    emit("\n  診斷 (c) 分量取 max（而非相加）—— 避免一個分量淹掉另一個")
    ks = [k for k in ["tmpl", "dt", "val"]
          if not ((k == "dt" and "dt" not in mode) or (k == "val" and "val" not in mode))]
    zs = []
    for k in ks:
        x = np.nan_to_num(comp[k], nan=0.0)
        good = x[y == 0]
        zs.append((x - np.median(good)) / max(np.percentile(good, 99) - np.median(good), 1e-6))
    mx = np.max(np.stack(zs), axis=0)
    thr = np.percentile(mx[y == 0], 99.9)
    per = "  ".join(f"[{a}] {int(((mx >= thr) & (typ == a)).sum())}/{int((typ == a).sum())}"
                    for a in ["S", "T", "R", "RP"] if (typ == a).sum())
    emit(f"    max     {average_precision_score(y, mx):>9.3f}"
         f"{roc_auc_score(y, mx):>10.3f}   {per}")


def combine(comp, mode, ref=None):
    """各分量用 val（純正常）的 median/IQR 標準化後相加。

    為什麼要標準化：三個 NLL 量綱完全不同（CE 是 nats，高斯 NLL 含 log σ），
    直接相加等於隨機加權。ref 由 val 集算出，測試集沿用同一組常數。
    """
    parts, stats = [], {}
    for k in ["tmpl", "dt", "val"]:
        if k == "dt" and "dt" not in mode:
            continue
        if k == "val" and "val" not in mode:
            continue
        x = comp[k]
        if ref is None:
            good = x[np.isfinite(x)]
            med = float(np.median(good)) if len(good) else 0.0
            iqr = float(np.subtract(*np.percentile(good, [75, 25]))) if len(good) else 1.0
            stats[k] = (med, max(iqr, 1e-6))
        else:
            stats[k] = ref[k]
        med, iqr = stats[k]
        parts.append(np.nan_to_num((x - med) / iqr, nan=0.0))
    return np.sum(parts, axis=0), stats


# ---------------------------------------------------------------------------
# 5. 主流程
# ---------------------------------------------------------------------------
def main():
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    if SCENARIO_FILTER:
        df = df[df.scenario.str.contains(SCENARIO_FILTER, na=False)]
    df = df.sort_values(["scenario", "seq_pos"]).reset_index(drop=True)
    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].unique()))}
    df["tid"] = df["template_id"].map(vocab)
    V = len(vocab)

    scen = list(df.scenario.unique())
    base_scen = [s for s in scen if "baseline" in s]
    test_scen = [s for s in scen if "baseline" not in s]
    if not base_scen or not test_scen:
        emit("缺 baseline 或測試場景"); return

    emit("=" * 74)
    emit("多變量序列模型 —— 同時預測下一步的 (模板, 同源間隔, 距離值)")
    emit("=" * 74)
    emit(f"詞彙量 V={V}   窗長={WINDOW}   分流 STREAM_KEY={STREAM_MODE}"
         f"（{SOURCE_COL}）")
    emit(f"訓練場景 {len(base_scen)} 個 / 測試場景 {len(test_scen)} 個")

    # ---- baseline 時序切 train/val，再各自分流（與 ngram_detector 同口徑）----
    tr_segs, va_segs = [], []
    for s in base_scen:
        sub = df[df.scenario == s]
        cut = int(len(sub) * (1 - VAL_FRAC))
        tr_segs += split_segments(sub.iloc[:cut], STREAM_MODE)
        va_segs += split_segments(sub.iloc[cut:], STREAM_MODE)
    te_segs = [sg for s in test_scen
               for sg in split_segments(df[df.scenario == s], STREAM_MODE)]

    # 值的正規化常數只由 train 算（不可偷看 val/test）
    tr_idx = np.concatenate([i for _, i in tr_segs])
    tv = df.loc[tr_idx, "dist"].values.astype(float)
    tv = tv[np.isfinite(tv)]
    norm = (float(tv.mean()), float(tv.std() + 1e-9))
    emit(f"距離值正規化（僅由 train 估）: mean={norm[0]:.3f} std={norm[1]:.3f}")

    Wtr = segments_to_windows(df, tr_segs, norm)
    Wva = segments_to_windows(df, va_segs, norm)
    Wte = segments_to_windows(df, te_segs, norm)
    if Wtr is None or Wte is None:
        emit("視窗不足"); return
    emit(f"訓練視窗 {len(Wtr[0])}   val 視窗 {len(Wva[0]) if Wva else 0}   "
         f"測試視窗 {len(Wte[0])}")

    pos = Wte[7]
    y = df.loc[pos, "label"].values.astype(int)
    typ = df.loc[pos, "attack_type"].values
    seen = df.loc[pos, "tid"].isin(set(np.unique(Wtr[3]))).values
    sec = (df.loc[pos, "scenario"].astype(str) + "|" + df.loc[pos, "ts_sec"].astype(str)).values
    emit(f"評估位置 {len(pos)} 行，異常 {int(y.sum())}"
         f"（{dict(pd.Series(typ[y == 1]).value_counts())}）")

    rows = []
    for mode in MODES:
        emit("\n" + "-" * 74)
        emit(f"消融設定：{mode}"
             + ("   ← 等同現行 DeepLog（只有模板）" if mode == "tmpl" else ""))
        emit("-" * 74)
        torch.manual_seed(SEED); np.random.seed(SEED)
        model = MVDeepLog(V, Wtr[2].shape[2])
        train(model, Wtr, mode)

        cva, _ = score(model, Wva, mode) if Wva else (None, None)
        s_va, ref = combine(cva, mode) if cva else (None, None)
        cte, pte = score(model, Wte, mode)
        s_te, _ = combine(cte, mode, ref)

        # 逐行分數 dump（供逐秒/離線分析）：DUMP_SCORES=1 時輸出
        if os.environ.get("DUMP_SCORES"):
            pd.DataFrame({
                "scenario": df.loc[pos, "scenario"].values,
                "ts_sec": df.loc[pos, "ts_sec"].values,
                "label": y, "attack_type": typ, "score": s_te,
            }).to_csv(os.path.join(OUT, f"mvdeeplog_scores{RESULT_SUFFIX}.csv"), index=False)
            # val（純正常、訓練期未使用）分數：供 second_level_eval 以 val 校準門檻，
            # 避免門檻取自評估集正常行而使誤報率變成恆等式。
            if s_va is not None:
                vpos = Wva[7]
                pd.DataFrame({
                    "scenario": df.loc[vpos, "scenario"].values,
                    "ts_sec": df.loc[vpos, "ts_sec"].values,
                    "score": s_va,
                }).to_csv(os.path.join(OUT, f"mvdeeplog_valscores{RESULT_SUFFIX}.csv"),
                          index=False)

        for tag, m in [("全量", np.ones(len(y), bool)), ("seen-only", seen)]:
            yy, ss, tt = y[m], s_te[m], typ[m]
            if yy.sum() == 0:
                continue
            ap = average_precision_score(yy, ss)
            roc = roc_auc_score(yy, ss)
            per = "  ".join(
                f"[{a}] {int(((ss >= np.percentile(ss[yy == 0], OP_PCTL)) & (tt == a)).sum())}"
                f"/{int((tt == a).sum())}"
                for a in ["S", "T", "R", "RP"] if (tt == a).sum())
            emit(f"  ({tag}) PR-AUC={ap:.3f}  ROC-AUC={roc:.3f}")
            emit(f"           thr=正常 p{OP_PCTL:g} 時逐類命中: {per}")
            if tag == "全量":
                # 整體 precision/recall/F1（在多個運作點，供論文 Table 2）
                for op in sorted({99.9, 99.5, OP_PCTL}):
                    thr = np.percentile(ss[yy == 0], op)
                    pred = ss >= thr
                    tp = int((pred & (yy == 1)).sum())
                    fp = int((pred & (yy == 0)).sum())
                    fn = int((~pred & (yy == 1)).sum())
                    P = tp / (tp + fp) if tp + fp else 0.0
                    R = tp / (tp + fn) if tp + fn else 0.0
                    F = 2 * P * R / (P + R) if P + R else 0.0
                    emit(f"           @p{op:g}: precision={P:.3f} recall={R:.3f} "
                         f"F1={F:.3f}  (TP={tp} FP={fp} FN={fn})")
            if tag == "seen-only":
                rows.append((mode, ap, roc, per))

        d = pd.DataFrame({"sec": sec, "s": s_te, "y": y}).groupby("sec").agg(
            s=("s", "max"), y=("y", "max"))
        emit(f"  (逐秒) PR-AUC={average_precision_score(d.y, d.s):.3f}"
             f"   秒數={len(d)} 異常秒={int(d.y.sum())}")

        diagnose(df, Wte, cte, pte, y, typ, mode)

    emit("\n" + "=" * 74)
    emit("消融總表（seen-only）")
    emit("=" * 74)
    emit(f"{'設定':<16}{'PR-AUC':>9}{'ROC-AUC':>10}   逐類命中 @ 正常 p{OP_PCTL:g}")
    emit("-" * 74)
    for mode, ap, roc, per in rows:
        emit(f"{mode:<16}{ap:>9.3f}{roc:>10.3f}   {per}")
    emit("")
    emit("可證偽的預測：加上 dt 之後 S 必須明顯上升、RP 必須接近 100%。")
    emit("若 tmpl → tmpl+dt 的 S 沒有動，本設計的前提就是錯的。")

    # RESULT_SUFFIX：同一支腳本會被不同 SCENARIO_FILTER 連跑數次（Snaive / Sphys /
    # 全量），固定檔名會讓後跑的把前跑的結果蓋掉，事後分不出哪份對應哪個威脅模型。
    p = os.path.join(OUT, f"mvdeeplog_results{RESULT_SUFFIX}.txt")
    open(p, "w", encoding="utf-8").write("\n".join(log) + "\n")
    print(f"\n報告已存: {p}")


if __name__ == "__main__":
    main()
