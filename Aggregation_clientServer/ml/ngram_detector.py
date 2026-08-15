#!/usr/bin/env python3
# =============================================================================
# ngram_detector.py ── n-gram / bigram 頻率統計模型的序列異常檢測
# =============================================================================
# 動機：DeepLog（deeplog.py）用 LSTM 學「前 h 個模板 → 下一個模板」。
#       n-gram 是同一件事的『零訓練、可解釋』版本：直接數頻率，不做梯度下降。
#       它是 DeepLog 的對照組 —— 如果 n-gram 就打平 LSTM，那 LSTM 的複雜度
#       在這批 log 上沒有換到東西，這本身就是一個可以寫進論文的結論。
#
# 模型：對模板 ID 序列 s_1..s_T，用 baseline（純正常）場景估計
#           P(s_i | s_{i-n+1} .. s_{i-1})
#       add-k（Lidstone）平滑，異常分數 = surprisal = -log P。
#       n=1 退化成「模板本身有多罕見」，n=2 是 bigram（轉移罕見度），n=3/4 同理。
#
# ⚠ 洩漏拆解（延續 deeplog.py 結尾與 ablation_leakage.py 的立場）：
#       本機無 GPIO，真 motor 不會產生 "too close/safe" 模板，所以 R 攻擊插入的
#       模板在正常訓練集裡「從未出現過」。任何序列模型都會因此免費抓到 R，
#       但那是模板新穎性(unigram)的功勞，不是序列知識(bigram)的功勞。
#       因此本腳本一律分兩層報告：
#         (A) 全量        —— 含新模板，數字好看但有洩漏
#         (B) seen-only   —— 只評估「目標模板在訓練集出現過」的行，
#                            此時唯一的訊號來源就是轉移機率 → bigram 的真實貢獻
#
# 資料切分：
#   train = baseline_* 場景的前 80%（純正常）
#   val   = baseline_* 場景的後 20%（純正常，只用來定閾值 / 估 FPR）
#   test  = 其餘含攻擊場景，用 parsed_all.csv 的 label 評估
#
# ⚠ 反交錯（de-interleave，STREAM_KEY）——多來源聚合 log 的必要前處理：
#       aggregation_server 把 N 組 pair 的 log 匯進同一份檔案，所以檔案順序是
#       N 條各自規律的循環『隨機交錯』的結果。誰先寫進來由排程與網路抖動決定，
#       不由前一行決定 —— 於是 bigram 的「前一個模板」幾乎不帶資訊。
#       topo3（三組 1:1）實測：H(next|prev) 交錯 1.47 bits → 依 pair 分流 0.38 bits，
#       seen-only PR-AUC 0.087 → 0.776。
#       關鍵在『分流的邊界要對齊因果單元』：motor i 只訂閱 sensor i，所以
#       Sensor_i + Motor_i 必須留在同一條流；改成每個 SourceName 各一條會切斷
#       這條因果鏈，S/RP 直接歸零（PR-AUC 掉回 0.503）。用 --compare-streams 複現。
#
# ⚠ 信任模型（SOURCE_FIELD，見下方常數說明）——序列模型只在一種前提下有意義：
#       主評估預設 SOURCE_FIELD=sourcename，前提是**攻擊者已繞過身分驗證**。
#       只有這時孤兒規則失效、序列異常才是唯一的偵測手段。sourcenode 下 S/R/RP 被
#       零訓練的孤兒規則以 precision 1.000 全接走，量序列模型沒有意義（跑一次當
#       baseline 即可）。這是刻意的預設，不要 naive 跑 sourcenode 就當成頭條數字。
#
# 執行： ml/venv/bin/python ml/ngram_detector.py                    # 預設 sourcename
#        STREAM_KEY=pair ml/venv/bin/python ml/ngram_detector.py
#        ml/venv/bin/python ml/ngram_detector.py --compare-streams
#        SOURCE_FIELD=sourcenode ml/venv/bin/python ml/ngram_detector.py  # 一次性 baseline
# 輸出： ml/out/ngram_results.txt   （報告；STREAM_KEY!=none 或 sourcenode 時檔名加後綴）
#        ml/out/ngram_scores.csv    （逐行分數，供 make_figures / 融合使用）
# =============================================================================
import os
import sys
import math
from collections import defaultdict, Counter

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, roc_auc_score,
                             precision_recall_fscore_support, confusion_matrix)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")

# ---- 超參數 ----
NS         = [1, 2, 3, 4]   # 要比較的 n（2 = bigram，本次主角）
ALPHA      = 0.1            # add-k 平滑係數
VAL_FRAC   = 0.2            # baseline 尾端切多少當 val（定閾值用）
ATTACKS    = ["S", "T", "R", "RP"]
ORPHAN     = "__orphan__"   # 無法歸屬來源的行（見 stream_key 的說明）
# 分流鍵取自哪個欄位。這是**信任模型**的選擇，不是實作細節：
#   sourcename（預設，主評估）—— 訊息文字裡『自稱』的 lr_SourceName。
#       前提假設：**攻擊者已取得合法身分 / 繞過 SourceNode 蓋章**。偽造行帶著合法
#       pair 的身分混進正常流，孤兒規則失效 → 唯一還能抓它的就是「行為序列異常」。
#       這是唯一值得量序列模型的威脅模型，故設為預設。報告請標明此前提。
#   sourcenode（一次性 baseline）—— server 依 session 蓋章的 lr_SourceNode。
#       匿名寫入被蓋成 "unverified" → 落進孤兒流，被零訓練的孤兒規則以 precision 1.000
#       全數接走。此時 S/R/RP 的偵測與序列模型無關（同 R 消融實驗證明的「資料指紋」），
#       T 又不是序列訊號 → 序列模型在此無可證明的價值。
#       它的用途只有一個：證明「孤兒規則讓 S/R/RP 變 trivial，所以序列模型只在身分
#       被繞過時才需要被測」——即 sourcename 的正當性論證。跑一次即可，不是並列對照。
SOURCE_FIELD = os.environ.get("SOURCE_FIELD", "sourcename").strip().lower()
if SOURCE_FIELD not in ("sourcenode", "sourcename"):
    raise SystemExit(f"SOURCE_FIELD 只能是 sourcenode/sourcename，收到 {SOURCE_FIELD!r}")
SOURCE_COL = ("lr_SourceNode" if SOURCE_FIELD == "sourcenode" else "lr_SourceName")
# 每條序列開頭要跳過的行數（暖機）。序列剛開始時 context 是 padding，分數天生偏高。
# ⚠ 分流後這件事被放大：流數 ×N ⇒ 序列開頭也 ×N，不跳的話 FP 會被灌水，
#   而且『不分流』只有一個開頭、『分流』有 N 個，跨粒度比較會不公平。
#   預設 10 與 compare_ngram_deeplog.py 的口徑一致。設 WARMUP=0 可還原舊行為。
WARMUP     = int(os.environ.get("WARMUP", "10"))


# --------------------------------------------------------------------------
# 資料
# --------------------------------------------------------------------------
def load():
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    # 場景過濾：parse_logs.py 會把 attacks/logs 下『所有』批次 glob 進來（含舊批），
    # 但舊批是用有 bug 的 motor 採的，benign 分佈與新批不一致。設 SCENARIO_FILTER
    # 環境變數（子字串比對）即可只留某一批做乾淨的 before/after。例：
    #   SCENARIO_FILTER=20260811 ml/venv/bin/python ml/ngram_detector.py
    filt = os.environ.get("SCENARIO_FILTER", "").strip()
    if filt:
        df = df[df["scenario"].str.contains(filt, regex=False)].copy()
    # vocab 在過濾『之後』才建，確保詞彙量反映實際用到的模板
    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].astype(str).unique()))}
    df["tid"] = df["template_id"].astype(str).map(vocab)
    df = df.sort_values(["scenario", "seq_pos"]).reset_index(drop=True)
    return df, vocab


def stream_key(name, mode):
    """把一行 log 指派到一條『行為序列』。

    mode:
      none    不分流 —— 整個場景一條，即檔案原始順序（N 條流交錯的結果）。
              保留為預設值，讓既有結果可重現。
      pair    依**因果單元**分流 —— Sensor_i 與 Motor_i 同一條流。
              理由：motor i 只訂閱 sensor i，`Updated → Received → Safe/TooClose`
              這個循環才是真正的行為序列。這是建議值。
      source  依**身分**分流 —— 每個 SourceName 各一條。
              會把 sensor↔motor 的因果鏈剪斷，S/RP 的破綻隨之消失；
              留著是為了當對照組，證明「分流粒度」比「有沒有分流」更關鍵。

    輸入是 SOURCE_COL 欄位的值，兩種格式都吃：
      lr_SourceNode  "ns=1;s=SensorSource2" / "unverified" / NaN
      lr_SourceName  "Sensor2" / "System" / NaN

    ⚠ 地雷：無法歸屬的行（NaN、空值，或 server 蓋章為 "unverified" 的匿名寫入）
      一律自成 ORPHAN 流，**絕不可**預設併進 pair1。那會讓攻擊者的匿名寫入污染
      正常流的轉移統計，而且「孤兒流存在」本身就是最強的告警訊號
      （eval_v2.py 的 SourceNode 規則在 v2 資料上達 precision 1.000，靠的正是這件事）。
    """
    if mode == "none":
        return "all"
    if name is None or (isinstance(name, float) and math.isnan(name)):
        return ORPHAN
    s = str(name).strip()
    if s in ("", "nan", "None", "null"):
        return ORPHAN
    # server 蓋章格式：剝掉 "ns=1;s=" 前綴，取節點名（SensorSource2 / MotorSource3）。
    if ";s=" in s:
        s = s.split(";s=", 1)[1]
    # server 明確標示『無法驗證來源』—— 這正是匿名寫入的指紋，必須進孤兒流。
    if s == "unverified":
        return ORPHAN
    if mode == "source":
        return s
    # mode == "pair"：只有設備行有 pair 歸屬。SensorSource2 / Sensor2 都要認得。
    # System 之類非設備行自成一流，不能塞進任何 pair（不參與 sensor→motor 循環）。
    if s.startswith(("Sensor", "Motor")):
        return "pair" + (s[-1] if s[-1].isdigit() else "1")
    return "other:" + s


def split_segments(sub, mode="none"):
    """把一段（已依 seq_pos 排序的）log 切成若干條序列。

    回傳 [(tid 陣列, DataFrame 索引), ...]。mode="none" 時只回傳一條，
    行為與分流前完全一致。分流鍵排序後輸出，確保串接順序可重現、
    且分數與標籤逐一對齊。
    """
    if mode == "none":
        return [(sub["tid"].values, sub.index.values)]
    keys = sub[SOURCE_COL].map(lambda v: stream_key(v, mode))
    return [(g["tid"].values, g.index.values)
            for _, g in sub.groupby(keys, sort=True)]


def scenario_segments(df, scen, mode="none"):
    """把一個場景切成若干條序列。"""
    return split_segments(df[df.scenario == scen], mode)


def scenario_seq(df, scen):
    """回傳某場景依序的 (tid 陣列, 對應的 DataFrame 索引)。（不分流，保留舊介面）"""
    return scenario_segments(df, scen, "none")[0]


# --------------------------------------------------------------------------
# n-gram 模型
# --------------------------------------------------------------------------
class NGram:
    """add-k 平滑的 n-gram 模型。n=1 時 context 為空 tuple（純模板頻率）。"""

    def __init__(self, n, vocab_size, alpha=ALPHA):
        self.n = n
        self.V = vocab_size
        self.alpha = alpha
        self.ctx_next = defaultdict(Counter)   # context tuple -> Counter(next tid)
        self.ctx_tot  = Counter()              # context tuple -> 總次數
        self.seen_uni = set()                  # 訓練集出現過的模板（做 seen-only 用）

    def fit_seq(self, seq):
        """餵入一整段正常序列。序列開頭用 -1 當 padding 上下文。"""
        pad = [-1] * (self.n - 1)
        s = pad + list(seq)
        for i in range(self.n - 1, len(s)):
            ctx = tuple(s[i - self.n + 1:i])
            self.ctx_next[ctx][s[i]] += 1
            self.ctx_tot[ctx] += 1
            self.seen_uni.add(s[i])

    def surprisal(self, seq):
        """回傳每個位置的 -log P（自然對數），長度與 seq 相同。

        同時回傳 unseen_ctx / unseen_trans 兩個布林陣列，用來把
        『上下文沒見過』與『上下文見過但這個轉移沒見過』分開診斷。
        """
        pad = [-1] * (self.n - 1)
        s = pad + list(seq)
        out, unseen_ctx, unseen_trans = [], [], []
        denom_backoff = math.log(self.V)   # context 全新時退化成均勻分布
        for i in range(self.n - 1, len(s)):
            ctx = tuple(s[i - self.n + 1:i])
            nxt = s[i]
            tot = self.ctx_tot.get(ctx, 0)
            if tot == 0:
                # context 從未出現 → 沒有任何資訊，退回均勻分布（不誇大分數）
                out.append(denom_backoff)
                unseen_ctx.append(True)
                unseen_trans.append(True)
                continue
            cnt = self.ctx_next[ctx].get(nxt, 0)
            p = (cnt + self.alpha) / (tot + self.alpha * self.V)
            out.append(-math.log(p))
            unseen_ctx.append(False)
            unseen_trans.append(cnt == 0)
        return np.array(out), np.array(unseen_ctx), np.array(unseen_trans)


# --------------------------------------------------------------------------
# 評估工具
# --------------------------------------------------------------------------
def eval_block(y_true, score, thr, title, emit):
    """在給定閾值下印出 precision/recall/f1 + 混淆矩陣 + PR-AUC。"""
    pred = (score >= thr).astype(int)
    ap = average_precision_score(y_true, score) if y_true.sum() else float("nan")
    try:
        auc = roc_auc_score(y_true, score) if y_true.sum() else float("nan")
    except ValueError:
        auc = float("nan")
    p, r, f, _ = precision_recall_fscore_support(
        y_true, pred, average="binary", zero_division=0)
    emit(f"  {title}")
    emit(f"    PR-AUC={ap:.3f}  ROC-AUC={auc:.3f}  "
         f"| thr={thr:.3f}  precision={p:.3f}  recall={r:.3f}  f1={f:.3f}")
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    emit(f"    TP={tp} FP={fp} FN={fn} TN={tn}  "
         f"FPR={fp / max(tn + fp, 1):.4%}")
    return dict(ap=ap, auc=auc, precision=p, recall=r, f1=f,
                tp=tp, fp=fp, fn=fn, tn=tn)


def main(mode=None):
    df, vocab = load()
    V = len(vocab)
    log = []
    mode = mode or os.environ.get("STREAM_KEY", "none").strip().lower()
    if mode not in ("none", "pair", "source"):
        raise SystemExit(f"STREAM_KEY 只能是 none/pair/source，收到 {mode!r}")

    def emit(s=""):
        print(s)
        log.append(str(s))

    emit("=" * 72)
    emit("n-gram / bigram 頻率統計模型 —— log 序列異常檢測")
    emit("=" * 72)
    emit(f"模板詞彙量 V={V}   總行數={len(df)}   add-k alpha={ALPHA}")
    emit(f"反交錯 STREAM_KEY={mode}   "
         f"（none=原始交錯 / pair=依因果單元 / source=依身分）")
    emit(f"分流鍵欄位 SOURCE_FIELD={SOURCE_FIELD} → {SOURCE_COL}")
    if SOURCE_FIELD == "sourcename":
        emit("  ⚠ 主評估前提：**假設攻擊者已繞過身分驗證**（偽造行帶合法 pair 身分，")
        emit("    孤兒規則失效）。以下序列模型的偵測力即『身分被繞過時的第二道防線』。")
    else:
        emit("  ℹ baseline：server 蓋章可信，S/R/RP 全落孤兒流、被孤兒規則以 precision")
        emit("    1.000 全接走。此模式下序列模型的分數僅供對照，不代表其獨立偵測價值。")

    scen = sorted(df["scenario"].unique())
    # 用『包含 baseline』而非 startswith：baseline_180min / v2_baseline_* /
    # topo3_baseline_* / densitysweep_baseline_* 都要被選為訓練集。
    # 與 deeplog.py / compare_ngram_deeplog.py 的切分口徑一致。
    base_scen = [s for s in scen if "baseline" in s]
    test_scen = [s for s in scen if "baseline" not in s]
    if not base_scen:
        emit("沒有 baseline 場景可當訓練集，請先跑 collect_baseline.sh")
        return
    emit(f"訓練場景(純正常): {base_scen}")
    emit(f"測試場景(含攻擊): {test_scen}")

    # ---- baseline 切 train / val（時序切，不打散：保留序列結構）----
    # 先在場景層做時序切分（確保 val 嚴格晚於 train），再各自分流成多條序列。
    train_seqs, val_seqs = [], []
    for s in base_scen:
        sub = df[df.scenario == s]
        cut = int(len(sub) * (1 - VAL_FRAC))
        train_seqs += [seq for seq, _ in split_segments(sub.iloc[:cut], mode)]
        val_seqs   += [seq for seq, _ in split_segments(sub.iloc[cut:], mode)]
    n_train = sum(len(x) for x in train_seqs)
    n_val   = sum(len(x) for x in val_seqs)
    emit(f"train={n_train} 行(純正常)   val={n_val} 行(純正常, 只用來定閾值)")
    if mode != "none":
        emit(f"訓練序列條數={len(train_seqs)}  val 序列條數={len(val_seqs)}"
             f"   （模型只有一個，共用統計；分開的只有各流的 context）")

    # ---- 測試集切分（各 n 共用；與下方算分數的迭代順序完全一致）----
    # 每條流各自跳過 WARMUP 行：序列開頭的 context 是 padding，分數天生偏高，
    # 而分流後開頭數量 ×流數，不跳會讓 FP 隨分流粒度灌水。
    test_segs = [(seq, idx) for s in test_scen
                 for seq, idx in split_segments(df[df.scenario == s], mode)]
    test_idx = np.concatenate([idx[WARMUP:] for _, idx in test_segs])
    y_line   = df.loc[test_idx, "label"].values.astype(int)
    typ_line = df.loc[test_idx, "attack_type"].values
    sec_key  = (df.loc[test_idx, "scenario"].astype(str) + "|" +
                df.loc[test_idx, "ts_sec"].astype(str)).values
    emit(f"測試集 {len(y_line)} 行，其中異常 {int(y_line.sum())} 行")

    # ---- 流別清單：孤兒流一定要顯眼，它本身就是告警 ----
    if mode != "none":
        all_keys = df[SOURCE_COL].map(lambda v: stream_key(v, mode))
        emit()
        emit(f"流別清單（{all_keys.nunique()} 條）:")
        for k, cnt in all_keys.value_counts().items():
            n_anom = int(df.loc[all_keys == k, "label"].sum())
            mark = "  ⚠ 無法歸屬來源 —— 此流存在本身即為告警" if k == ORPHAN else ""
            emit(f"    {k:<16} {cnt:>7} 行  (異常 {n_anom}){mark}")

    results = {}
    score_cols = {}

    for n in NS:
        emit()
        emit("=" * 72)
        emit(f"n = {n}   （{'unigram：純模板罕見度' if n == 1 else f'{n}-gram：前 {n-1} 個模板 → 下一個'}）")
        emit("=" * 72)

        model = NGram(n, V)
        for seq in train_seqs:
            model.fit_seq(seq)
        emit(f"學到的 context 數: {len(model.ctx_tot)}   "
             f"訓練集出現過的模板: {len(model.seen_uni)}/{V}")

        # ---- val（純正常）分數：用來定零誤報閾值 ----
        val_scores = []
        for seq in val_seqs:
            sc, _, _ = model.surprisal(seq)
            val_scores.append(sc[WARMUP:])
        val_scores = [v for v in val_scores if len(v)]
        val_scores = np.concatenate(val_scores) if val_scores else np.array([0.0])
        thr = float(val_scores.max()) if len(val_scores) else 0.0
        emit(f"val 正常分數: 中位數={np.median(val_scores):.3f} "
             f"p99={np.percentile(val_scores, 99):.3f} max={val_scores.max():.3f}")
        emit(f"→ 閾值取 val 的 max（在未見過的正常資料上零誤報）: thr={thr:.3f}")

        # ---- test 分數（逐條流各自帶自己的 context，不跨流串接）----
        parts_sc, parts_uctx, parts_utr = [], [], []
        for seq, _ in test_segs:
            sc, uctx, utr = model.surprisal(seq)
            parts_sc.append(sc[WARMUP:]); parts_uctx.append(uctx[WARMUP:])
            parts_utr.append(utr[WARMUP:])
        score = np.concatenate(parts_sc)
        unseen_trans = np.concatenate(parts_utr)

        # 目標模板是否在訓練集出現過（seen-only 評估用）
        tids = df.loc[test_idx, "tid"].values
        seen_mask = np.array([t in model.seen_uni for t in tids])

        score_cols[f"ngram{n}"] = score

        # ---- (A) 全量：含新模板（有洩漏，但這是一般論文會報的數字）----
        emit()
        emit("(A) 全量評估 —— 含訓練集沒出現過的新模板")
        ra = eval_block(y_line, score, thr, "line-level", emit)

        # 逐秒聚合（對齊專案既有的『注入秒』口徑）
        sec_df = pd.DataFrame({"k": sec_key, "y": y_line, "s": score})
        g = sec_df.groupby("k").agg(y=("y", "max"), s=("s", "max"))
        eval_block(g["y"].values, g["s"].values, thr, "second-level（每秒取 max 分數）", emit)

        # ---- 各攻擊類別 recall ----
        emit("    各攻擊類別 recall:")
        pred = (score >= thr).astype(int)
        for at in ATTACKS:
            m = typ_line == at
            if m.sum() == 0:
                continue
            emit(f"      [{at}] {int(pred[m].sum())}/{int(m.sum())} = "
                 f"{pred[m].sum() / m.sum():.0%}")

        # ---- (B) seen-only：拿掉模板新穎性，只剩轉移資訊 ----
        emit()
        emit("(B) seen-only 評估 —— 只保留『目標模板訓練集見過』的行")
        emit(f"    保留 {int(seen_mask.sum())}/{len(seen_mask)} 行，"
             f"其中異常 {int(y_line[seen_mask].sum())} 行")
        if y_line[seen_mask].sum() > 0:
            rb = eval_block(y_line[seen_mask], score[seen_mask], thr,
                            "line-level (seen-only)", emit)
            emit("    各攻擊類別 recall (seen-only):")
            pb = (score[seen_mask] >= thr).astype(int)
            tb = typ_line[seen_mask]
            for at in ATTACKS:
                m = tb == at
                if m.sum() == 0:
                    continue
                emit(f"      [{at}] {int(pb[m].sum())}/{int(m.sum())} = "
                     f"{pb[m].sum() / m.sum():.0%}")
        else:
            rb = None
            emit("    ⚠ 移除新模板後測試集已無任何異常行 —— 代表此 n 的偵測力"
                 "**完全**來自模板新穎性，序列資訊貢獻為零。")

        # ---- 純規則版：unseen transition（不用閾值，最可解釋的形式）----
        if n >= 2:
            emit()
            emit("(C) 純規則版 —— 「這個轉移在正常資料中從未出現過」直接告警")
            pr, rr, fr, _ = precision_recall_fscore_support(
                y_line, unseen_trans.astype(int), average="binary", zero_division=0)
            tn, fp, fn, tp = confusion_matrix(
                y_line, unseen_trans.astype(int), labels=[0, 1]).ravel()
            emit(f"    precision={pr:.3f} recall={rr:.3f} f1={fr:.3f}  "
                 f"TP={tp} FP={fp} FN={fn} TN={tn}")

        results[n] = dict(full=ra, seen=rb)

    # ---- 橫向比較表 ----
    emit()
    emit("=" * 72)
    emit("橫向比較（line-level）")
    emit("=" * 72)
    emit(f"{'n':>3} | {'PR-AUC(全量)':>12} | {'F1(全量)':>9} | "
         f"{'PR-AUC(seen)':>12} | {'F1(seen)':>9}")
    emit("-" * 60)
    for n in NS:
        a = results[n]["full"]
        b = results[n]["seen"]
        bs = (f"{b['ap']:>12.3f} | {b['f1']:>9.3f}") if b else f"{'n/a':>12} | {'n/a':>9}"
        emit(f"{n:>3} | {a['ap']:>12.3f} | {a['f1']:>9.3f} | {bs}")

    emit()
    emit("=" * 72)
    emit("解讀")
    emit("=" * 72)
    emit("- n=1（unigram）沒有任何序列資訊，純粹是『這個模板有多罕見』。")
    emit("  n>=2 相對 n=1 的增益，才是 bigram/n-gram 真正買到的東西。")
    emit("- (A)(B) 的落差就是洩漏的大小：本機無 GPIO，R 攻擊插入的 motor 模板")
    emit("  在正常訓練集不存在，任何序列模型都會免費抓到 —— 那不是序列知識。")
    emit("  要引用『n-gram 有效』的結論，請用 (B) 的數字。")
    emit("- 閾值取 val（未見過的正常資料）的 max，是刻意保守的零誤報設定；")
    emit("  要換操作點看 PR-AUC 即可，那與閾值無關。")
    emit("- 與 deeplog_results.txt 對照：若 n-gram 打平 LSTM，代表這批 log 的")
    emit("  序列結構短且規律，LSTM 的長程記憶沒有用武之地。")
    if mode == "none":
        emit("- ⚠ 本次 STREAM_KEY=none：若資料含多組 pair（topo3_*），檔案順序是多條")
        emit("  流交錯的結果，量到的多半是排程雜訊。請用 STREAM_KEY=pair 重跑，")
        emit("  或用 --compare-streams 看三種粒度的對照。")

    # sourcename 是主評估（預設）→ 寫正規檔名；sourcenode 是 baseline → 加後綴。
    suffix = "" if mode == "none" else f"_{mode}"
    if SOURCE_FIELD == "sourcenode":
        suffix += "_sourcenode"
    with open(os.path.join(OUT, f"ngram_results{suffix}.txt"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in log) + "\n")

    # 逐行分數存檔，供後續融合 / 畫圖
    sc_df = pd.DataFrame({
        "scenario": df.loc[test_idx, "scenario"].values,
        "seq_pos":  df.loc[test_idx, "seq_pos"].values,
        "ts_sec":   df.loc[test_idx, "ts_sec"].values,
        "label":    y_line,
        "attack_type": typ_line,
    })
    if mode != "none":
        sc_df["stream"] = df.loc[test_idx, SOURCE_COL].map(
            lambda v: stream_key(v, mode)).values
    for k, v in score_cols.items():
        sc_df[k] = v
    sc_df.to_csv(os.path.join(OUT, f"ngram_scores{suffix}.csv"), index=False)

    print(f"\n報告已存: {OUT}/ngram_results{suffix}.txt")
    print(f"逐行分數: {OUT}/ngram_scores{suffix}.csv")


# --------------------------------------------------------------------------
# --compare-streams：三種分流粒度的對照
# --------------------------------------------------------------------------
def cond_entropy(model):
    """模型學到的加權條件熵 H(next|context)，bits。越低代表序列越可預測。"""
    ents, tots = [], []
    for ctx, cnt in model.ctx_next.items():
        tot = model.ctx_tot[ctx]
        ps = np.array([c / tot for c in cnt.values()], dtype=float)
        ents.append(float(-(ps * np.log2(ps)).sum()))
        tots.append(tot)
    if not tots:
        return float("nan")
    return float(np.average(ents, weights=np.array(tots, dtype=float)))


def compare_streams(n=2):
    """同一批資料、同一個 n，只換分流粒度，看 seen-only 指標怎麼變。

    這是「反交錯該不該做、該分多細」的決定性對照：分流粒度必須對齊因果單元，
    分太細（source）會把 sensor↔motor 的因果鏈剪斷，比不分流好不了多少。
    """
    df, vocab = load()
    V = len(vocab)
    log = []

    def emit(s=""):
        print(s)
        log.append(str(s))

    scen = sorted(df["scenario"].unique())
    base_scen = [s for s in scen if "baseline" in s]
    test_scen = [s for s in scen if "baseline" not in s]

    emit("=" * 78)
    emit(f"反交錯粒度對照 —— n={n}，同一批資料、同一套超參，只換分流鍵")
    emit("=" * 78)
    emit(f"V={V}  訓練場景 {len(base_scen)} 個  測試場景 {len(test_scen)} 個")
    emit(f"分流鍵欄位 SOURCE_FIELD={SOURCE_FIELD} → {SOURCE_COL}")
    emit()

    rows = []
    for mode, desc in [("none",   "不分流（檔案原始順序＝多流交錯）"),
                       ("pair",   "依 pair 分流（Sensor_i+Motor_i 同組）★建議"),
                       ("source", "依 SourceName 分流（切斷 sensor↔motor）")]:
        model = NGram(n, V)
        # 先把所有 baseline 的 train 段餵完，才去算 val 分數。
        # ⚠ 不可邊 fit 邊 score：那樣第一個場景的 val 會用「只看過第一個場景」
        #   的模型評分，閾值會偏高，而且與 main() 不一致。
        train_parts, val_parts = [], []
        for s in base_scen:
            sub = df[df.scenario == s]
            cut = int(len(sub) * (1 - VAL_FRAC))
            train_parts += [sq for sq, _ in split_segments(sub.iloc[:cut], mode)]
            val_parts   += [sq for sq, _ in split_segments(sub.iloc[cut:], mode)]
        for seq in train_parts:
            model.fit_seq(seq)
        val = [model.surprisal(seq)[0][WARMUP:] for seq in val_parts]
        thr = float(np.concatenate([v for v in val if len(v)]).max())

        segs = [sg for s in test_scen
                for sg in split_segments(df[df.scenario == s], mode)]
        # 每條流各自跳過暖機段，否則流數多的粒度會被開頭的高分灌水
        idx = np.concatenate([i[WARMUP:] for _, i in segs])
        score = np.concatenate([model.surprisal(sq)[0][WARMUP:] for sq, _ in segs])
        y = df.loc[idx, "label"].values.astype(int)
        typ = df.loc[idx, "attack_type"].values
        seen = np.array([t in model.seen_uni for t in df.loc[idx, "tid"].values])

        y, score, typ = y[seen], score[seen], typ[seen]
        pred = score >= thr
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        ap = average_precision_score(y, score) if y.sum() else float("nan")
        n_streams = df[SOURCE_COL].map(
            lambda v: stream_key(v, mode)).nunique()

        # ---- 閾值懸崖診斷 ----
        # 分流後正常序列變得極度可預測，surprisal 只剩少數幾個相異值。
        # 「val 的 max」這個零誤報策略於是落在一個離散大團塊的邊緣：
        # 閾值挪動 0.01 就可能讓 FP 差一個數量級。所以此處的 F1/FP 不可直接引用，
        # 該粒度的真實可分性請看與閾值無關的 PR-AUC。
        uniq = np.unique(np.round(score, 6))
        nxt = uniq[uniq > thr + 1e-9]
        fp_next = int(((score >= nxt[0]) & (y == 0)).sum()) if len(nxt) else 0
        tp_next = int(((score >= nxt[0]) & (y == 1)).sum()) if len(nxt) else 0

        emit(f"── {desc}")
        emit(f"     流別數={n_streams}  轉移種類={len(model.ctx_next)}  "
             f"H(next|context)={cond_entropy(model):.3f} bits  thr={thr:.3f}")
        emit(f"     seen-only: PR-AUC={ap:.3f}  P={p:.3f} R={r:.3f} F1={f1:.3f}  "
             f"TP={tp} FP={fp} FN={fn}")
        emit(f"     ⚠ 閾值懸崖: 分數只有 {len(uniq)} 個相異值；"
             f"閾值抬到下一個相異值 {nxt[0]:.3f} → TP={tp_next} FP={fp_next}"
             + ("（FP 掉一個數量級，TP 不變）" if fp_next * 5 < fp and tp_next == tp else ""))
        per = "  ".join(
            f"[{a}] {int(pred[typ == a].sum())}/{int((typ == a).sum())}"
            for a in ATTACKS if (typ == a).sum())
        emit(f"     各類 recall: {per}")
        emit()
        rows.append((desc, n_streams, cond_entropy(model), ap, f1, fp))

    emit("=" * 78)
    emit(f"{'分流方式':<40} {'流數':>4} {'H(bits)':>8} {'PR-AUC':>7} "
         f"{'F1':>6} {'FP':>5}")
    emit("-" * 78)
    for d_, ns, h, ap, f1, fp in rows:
        emit(f"{d_:<40} {ns:>4} {h:>8.3f} {ap:>7.3f} {f1:>6.3f} {fp:>5}")
    emit()
    emit("解讀：")
    emit("  · 交錯之下『前一個模板』幾乎不帶資訊 —— H 高，模型學到的是排程雜訊。")
    emit("  · 分流粒度要對齊**因果單元**（motor i 只訂閱 sensor i）。")
    emit("    分太細（source）會剪斷 sensor→motor 因果鏈，S/RP 的破綻隨之消失。")
    emit("  · 模型只有一個、統計共用；分開的只是各流當下的 context。")
    emit("    這點在 pair 數變多時是生死問題 —— 否則訓練資料會被切成 N 份。")
    emit("  · ⚠ 請引用 PR-AUC，不要引用本表的 F1/FP。分流後正常序列太可預測，")
    emit("    surprisal 只剩約 10 個相異值，『val 的 max』這個零誤報閾值剛好卡在")
    emit("    一個離散大團塊的邊緣（見各段的閾值懸崖診斷）。閾值策略需要另外處理，")
    emit("    但那是操作點的問題，與『該不該分流』無關 —— PR-AUC 已經回答了後者。")
    emit("  · 想要現成可用的操作點，看 main() 的 (C) 純規則版：分流後")
    emit("    「這個轉移在正常資料中從未出現過」達 P=0.684 R=0.540 F1=0.603，")
    emit("    完全不需要閾值（不分流時只有 F1=0.272）。")

    with open(os.path.join(OUT, "ngram_stream_compare.txt"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {OUT}/ngram_stream_compare.txt")


if __name__ == "__main__":
    if "--compare-streams" in sys.argv:
        compare_streams()
    else:
        main()
