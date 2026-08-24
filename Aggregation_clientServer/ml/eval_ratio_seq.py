#!/usr/bin/env python3
# =============================================================================
# eval_ratio_seq.py ── 異常比例 vs 序列模型（bigram / DeepLog）的檢測準度
# =============================================================================
# 這支是 eval_ratio.py 的姊妹版：eval_ratio.py 掃的是第 1 層規則類偵測器，
# 這支把 **bigram 與 DeepLog(LSTM)** 接到同一套「固定異常池 + 稀釋正常行 +
# 重抽 N 次報 mean±std」的框架上，讓兩篇實驗的比例軸可以並排看。
#
# ⚠ 關鍵設計差異（為什麼不能照抄 eval_ratio.py 的做法）：
#   規則型偵測器是「逐行函數」——每行的判定只看該行自己的欄位，所以先抽樣
#   再算分數，跟先算分數再抽樣，結果完全一樣。
#   但 bigram / DeepLog 是**序列**模型：一行的 surprisal 取決於它前面 n-1
#   （或 WINDOW）行是什麼。若照抄 eval_ratio.py 把正常行隨機抽掉再餵給模型，
#   等於捏造出真實系統不會產生的假序列，量到的會是「序列被打斷」的假訊號，
#   不是比例效應。
#
#   ✅ 本腳本的做法：**分數只在完整、未被破壞的原始序列上算一次**，
#      比例重採樣只改變「哪些行進入評估集」。這樣指標差異純粹來自類別平衡，
#      與 eval_ratio.py 的實驗語意一致（同一批攻擊行稀釋在不同量的正常流量裡）。
#
# 切分 / 閾值：完全沿用 compare_ngram_deeplog.py
#   * train/val = baseline 場景的 80/20（純正常），兩個模型共用
#   * 評估位置 = 每個測試場景第 WINDOW 行之後（兩個模型索引集合相同）
#   * 閾值 = val（未見過的正常資料）分數的 max，即零誤報操作點
#   * 閾值在所有比例點固定不變 —— 它是在 val 上定的，本來就與測試集比例無關
#
# 順帶納入兩個規則型偵測器當參照線，方便和 ratio_results.txt 對照。
#
# 執行： SCENARIO_FILTER=20260811_002727 ml/venv/bin/python ml/eval_ratio_seq.py
#        （第二次起會讀 ratio_seq_scores.npz 快取，跳過 LSTM 重訓；
#          加 --retrain 可強制重算）
# 輸出： ml/out/ratio_seq_results.txt
#        ml/out/ratio_seq_summary.json
#        ml/out/ratio_seq.csv
# =============================================================================
import os
import sys
import json

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (average_precision_score,
                             precision_recall_fscore_support, confusion_matrix)

from ngram_detector import NGram, load, scenario_seq, VAL_FRAC, ATTACKS
from deeplog import DeepLog, WINDOW, HIDDEN, LAYERS, EPOCHS, BATCH, TOPK, LR

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
CACHE = os.path.join(OUT, "ratio_seq_scores.npz")

torch.manual_seed(42)
np.random.seed(42)

BEST_N = 2                                              # bigram 是甜蜜點
RATIOS = [0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.10]
REPEATS = 20

log = []


def emit(s=""):
    print(s)
    log.append(str(s))


# --------------------------------------------------------------------------
# 序列模型：在完整原始序列上算分（只做一次）
# --------------------------------------------------------------------------
def windows(seq):
    X, y, idx = [], [], []
    for i in range(len(seq) - WINDOW):
        X.append(seq[i:i + WINDOW])
        y.append(seq[i + WINDOW])
        idx.append(i + WINDOW)
    return np.array(X), np.array(y), np.array(idx)


def compute_scores(df, vocab):
    """回傳 dict：評估位置的索引、標籤、攻擊類別、各模型分數與閾值。"""
    V = len(vocab)
    scen = sorted(df["scenario"].unique())
    base = [s for s in scen if "baseline" in s]
    test = [s for s in scen if s not in base]
    emit(f"訓練(純正常): {base}")
    emit(f"測試(含攻擊): {len(test)} 個場景")

    train_seqs, val_seqs = [], []
    for s in base:
        seq, _ = scenario_seq(df, s)
        cut = int(len(seq) * (1 - VAL_FRAC))
        train_seqs.append(seq[:cut])
        val_seqs.append(seq[cut:])
    emit(f"train={sum(len(x) for x in train_seqs)} 行   "
         f"val={sum(len(x) for x in val_seqs)} 行   （兩個模型完全共用）")

    eval_idx, eval_off = [], {}
    for s in test:
        seq, idx = scenario_seq(df, s)
        _, _, off = windows(seq)
        eval_off[s] = off
        eval_idx.append(idx[off])
    eval_idx = np.concatenate(eval_idx)

    # ---- bigram ----
    ng = NGram(BEST_N, V)
    for s in train_seqs:
        ng.fit_seq(s)
    thr_ng = float(np.concatenate([ng.surprisal(s)[0] for s in val_seqs]).max())
    score_ng = np.concatenate(
        [ng.surprisal(scenario_seq(df, s)[0])[0][eval_off[s]] for s in test])

    # ---- DeepLog ----
    Xtr, ytr = [], []
    for s in train_seqs:
        X, yy, _ = windows(s)
        if len(X):
            Xtr.append(X)
            ytr.append(yy)
    Xtr, ytr = np.concatenate(Xtr), np.concatenate(ytr)
    emit(f"DeepLog 訓練視窗數: {len(Xtr)}（與 bigram 同一份 train 序列）")

    model = DeepLog(V, HIDDEN, LAYERS)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    lossf = nn.CrossEntropyLoss()
    ds = TensorDataset(torch.tensor(Xtr, dtype=torch.long),
                       torch.tensor(ytr, dtype=torch.long))
    dl = DataLoader(ds, batch_size=BATCH, shuffle=True)
    model.train()
    for ep in range(EPOCHS):
        tot = 0.0
        for xb, yb in dl:
            opt.zero_grad()
            loss = lossf(model(xb), yb)
            loss.backward()
            opt.step()
            tot += loss.item() * len(xb)
        emit(f"  epoch {ep + 1:2d}/{EPOCHS}  loss={tot / len(ds):.4f}")
    model.eval()

    def dl_score(seq):
        X, yn, _ = windows(seq)
        if len(X) == 0:
            return np.array([]), np.array([], dtype=bool)
        with torch.no_grad():
            logits = model(torch.tensor(X, dtype=torch.long))
            logp = torch.log_softmax(logits, dim=1).numpy()
            topk = torch.topk(logits, TOPK, dim=1).indices.numpy()
        sur = -logp[np.arange(len(yn)), yn]
        miss = np.array([yn[i] not in topk[i] for i in range(len(yn))])
        return sur, miss

    thr_dl = float(np.concatenate([dl_score(s)[0] for s in val_seqs]).max())
    sur_parts, miss_parts = [], []
    for s in test:
        sur, miss = dl_score(scenario_seq(df, s)[0])
        sur_parts.append(sur)
        miss_parts.append(miss)

    return dict(eval_idx=eval_idx,
                score_ng=score_ng, thr_ng=thr_ng,
                score_dl=np.concatenate(sur_parts), thr_dl=thr_dl,
                miss_dl=np.concatenate(miss_parts).astype(int))


# --------------------------------------------------------------------------
# 規則型參照線（逐行函數，與 eval_ratio.py 定義一致）
# --------------------------------------------------------------------------
def rule_layer1(d):
    return ((d["dist_ts_occurrence"].values > 1) |
            (d["session_denied_cumcount"].values > 1) |
            (d["sensor_events_in_sec_persrc"].values > 1)).astype(int)


def rule_sourcenode(d):
    sn = d["lr_SourceNode"].astype(str).str.strip().str.lower()
    return sn.isin(["unverified", "null", "none"]).astype(int)


# --------------------------------------------------------------------------
def score_metrics(y, pred, score=None):
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                 zero_division=0)
    tn, fp, _, _ = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    m = dict(precision=p, recall=r, f1=f, fpr=fp / max(tn + fp, 1), fp=int(fp))
    if score is not None and 0 < y.sum() < len(y):
        m["pr_auc"] = average_precision_score(y, score)
    else:
        m["pr_auc"] = float("nan")
    return m


def main():
    retrain = "--retrain" in sys.argv
    filt = os.environ.get("SCENARIO_FILTER", "").strip()

    emit("=" * 78)
    emit("異常比例 vs 序列模型（bigram / DeepLog）檢測準度")
    emit("=" * 78)
    emit(f"SCENARIO_FILTER = {filt or '(未設，使用 parsed_all.csv 全部場景)'}")

    df, vocab = load()

    if os.path.exists(CACHE) and not retrain:
        z = np.load(CACHE, allow_pickle=True)
        if str(z["filt"]) == filt and len(z["eval_idx"]) > 0:
            emit(f"（讀取分數快取 {os.path.basename(CACHE)}，跳過 LSTM 重訓；"
                 f"要重算加 --retrain）")
            S = {k: z[k] for k in ["eval_idx", "score_ng", "score_dl", "miss_dl"]}
            S["thr_ng"], S["thr_dl"] = float(z["thr_ng"]), float(z["thr_dl"])
        else:
            S = compute_scores(df, vocab)
            np.savez(CACHE, filt=filt, **S)
    else:
        S = compute_scores(df, vocab)
        np.savez(CACHE, filt=filt, **S)

    idx = S["eval_idx"]
    ev = df.loc[idx].copy().reset_index(drop=True)
    ev["_score_ng"] = S["score_ng"]
    ev["_score_dl"] = S["score_dl"]
    ev["_miss_dl"] = S["miss_dl"]
    ev["_rule_l1"] = rule_layer1(ev)
    ev["_rule_sn"] = rule_sourcenode(ev)
    ev["_rule_or"] = ((ev["_rule_l1"] == 1) | (ev["_rule_sn"] == 1)).astype(int)

    thr_ng, thr_dl = S["thr_ng"], S["thr_dl"]

    # 偵測器：(顯示名, 分數欄或 None, 判定函數)
    DETECTORS = [
        (f"bigram (n={BEST_N})", "_score_ng", lambda d: (d["_score_ng"].values >= thr_ng).astype(int)),
        ("DeepLog surprisal", "_score_dl", lambda d: (d["_score_dl"].values >= thr_dl).astype(int)),
        (f"DeepLog top-{TOPK} 規則", None, lambda d: d["_miss_dl"].values),
        ("[參照] 統計 OR SourceNode", None, lambda d: d["_rule_or"].values),
    ]

    anom = ev[ev.label == 1]
    norm = ev[ev.label == 0]
    n_a = len(anom)

    emit(f"評估位置 {len(ev)} 行（每場景跳過前 {WINDOW} 行）")
    emit(f"固定異常池 : {n_a} 筆  {anom.attack_type.value_counts().to_dict()}")
    emit(f"正常行池   : {len(norm)} 行   → 原始比例 {n_a / len(ev):.3%}")
    emit(f"閾值（val max，零誤報操作點，跨比例固定）: "
         f"bigram={thr_ng:.3f}  DeepLog={thr_dl:.3f}")
    emit(f"每個比例重複抽樣 {REPEATS} 次，報 mean ± std")
    emit()
    emit("各比例點共用同一批攻擊行與同一組分數 → 指標差異純粹來自類別平衡，")
    emit("不混入序列被破壞或不同次採集的干擾。")

    results = {name: {} for name, _, _ in DETECTORS}
    rows = []

    for p in RATIOS:
        # 先試「保留全部異常、稀釋正常行」；正常行不夠時改為縮減異常池
        n_norm = int(round(n_a * (1 - p) / p))
        if n_norm <= len(norm):
            mode, use_n, use_a = "dilute", n_norm, n_a
        else:
            mode = "subsample_anom"
            use_n = len(norm)
            use_a = max(1, int(round(p * use_n / (1 - p))))
        actual_p = use_a / (use_a + use_n)

        emit("\n" + "=" * 78)
        tail = "(稀釋正常行)" if mode == "dilute" else "(⚠ 已低於現有資料下限，改為抽樣縮減異常池)"
        emit(f"目標比例 {p:.3%}   →  {use_a} 異常 + {use_n} 正常 = {use_a + use_n} 行   {tail}")
        emit(f"實際比例 {actual_p:.3%}")
        emit("=" * 78)

        acc = {name: [] for name, _, _ in DETECTORS}
        for rep in range(REPEATS):
            rng = np.random.RandomState(1000 + rep)
            if mode == "dilute":
                a_part = anom
                n_part = norm.iloc[rng.choice(len(norm), size=use_n, replace=False)]
            else:
                a_part = anom.groupby("attack_type", group_keys=False).apply(
                    lambda g: g.sample(max(1, int(round(use_a * len(g) / len(anom)))),
                                       random_state=1000 + rep))
                n_part = norm
            sub = pd.concat([a_part, n_part])
            y = sub["label"].values.astype(int)
            for name, col, fn in DETECTORS:
                acc[name].append(score_metrics(
                    y, fn(sub), sub[col].values if col else None))

        for name, col, _ in DETECTORS:
            runs = acc[name]
            agg = {}
            for k in ["precision", "recall", "f1", "fpr", "fp", "pr_auc"]:
                v = np.array([r[k] for r in runs], dtype=float)
                # pr_auc 對沒有連續分數的規則型偵測器整欄都是 NaN（正常情況，非錯誤）
                agg[k] = ((float(np.nanmean(v)), float(np.nanstd(v)))
                          if np.isfinite(v).any() else (float("nan"), float("nan")))
            lift = agg["pr_auc"][0] / actual_p if actual_p > 0 else float("nan")
            results[name][f"{actual_p:.6f}"] = dict(
                target=p, actual=actual_p, mode=mode, n_anom=use_a, n_norm=use_n,
                repeats=len(runs), lift=lift,
                **{k: {"mean": agg[k][0], "std": agg[k][1]} for k in agg})
            pr = f"{agg['pr_auc'][0]:.3f}" if not np.isnan(agg["pr_auc"][0]) else "  -- "
            lf = f"{lift:>6.1f}" if not np.isnan(lift) else "    --"
            emit(f"  {name:<24} P={agg['precision'][0]:.3f}±{agg['precision'][1]:.3f}  "
                 f"R={agg['recall'][0]:.3f}±{agg['recall'][1]:.3f}  "
                 f"F1={agg['f1'][0]:.3f}±{agg['f1'][1]:.3f}  "
                 f"FPR={agg['fpr'][0]:.2%}  FP={agg['fp'][0]:.0f}  "
                 f"PR-AUC={pr}  lift={lf}")
            rows.append(dict(detector=name, target_ratio=p, actual_ratio=actual_p,
                             mode=mode, n_anom=use_a, n_norm=use_n,
                             **{k: agg[k][0] for k in agg},
                             **{k + "_std": agg[k][1] for k in agg},
                             lift=lift))

    # -----------------------------------------------------------------------
    cols = sorted({v["actual"] for v in results[DETECTORS[0][0]].values()})

    def table(title, key, fmt="{:>9.3f}"):
        emit("\n  " + title)
        emit("  " + f"{'偵測器':<24}" + "".join(f"{c:>9.2%}" for c in cols))
        for name, _, _ in DETECTORS:
            by = {v["actual"]: v for v in results[name].values()}
            row = f"  {name:<24}"
            for c in cols:
                if c not in by:
                    row += f"{'--':>9}"
                    continue
                val = by[c]["lift"] if key == "lift" else by[c][key]["mean"]
                row += f"{'--':>9}" if np.isnan(val) else fmt.format(val)
            emit(row)

    emit("\n" + "=" * 78)
    emit("趨勢摘要（欄=實際異常比例）")
    emit("=" * 78)
    table("F1（受比例影響，跨比例比大小沒意義）", "f1")
    table("recall @ 零誤報閾值（與比例無關 → 可跨比例比）", "recall")
    table("FPR（與比例無關 → 可跨比例比）", "fpr", "{:>8.2%} ")
    table("PR-AUC（基線=比例本身，絕對值不可跨比例比）", "pr_auc")
    table("lift = PR-AUC / 比例（除掉基線效應，可跨比例比）", "lift", "{:>9.1f}")

    emit("\n" + "=" * 78)
    emit("解讀")
    emit("=" * 78)
    emit("- recall 與 FPR 在各比例點基本是**常數**（在此設計下必然如此）：閾值固定在 val 上，")
    emit("  每行的分數也固定，稀釋正常行只改變兩個母體的相對大小，不改變各自母體內的比率。")
    emit("  這正是重點 —— 它把『比例效應』和『模型能力』乾淨地切開。")
    emit("  ⚠ 例外：≤0.5% 的點因為正常行不夠、改成縮減異常池，異常樣本本身變少且四類")
    emit("    比例會抖動，所以 recall 在那幾欄有小幅波動（非模型變化，是抽樣雜訊）。")
    emit("- precision / F1 隨比例下降而崩潰：同樣的 FPR 在越低的比例下製造越多絕對誤報，")
    emit("  淹沒真異常。所以報告裡的 F1 只在該比例下成立。")
    emit("- 要跨比例比較模型，看 recall@0FP、FPR、或 lift。lift 遠大於 1 才代表真的比亂猜強。")
    emit("- 對序列模型特別要注意：低比例時 bigram 的 FPR（較高）會比 DeepLog 更快吃掉 precision，")
    emit("  這解釋了為什麼在 line-level PR-AUC 打平的兩個模型，在真實的低比例場景下")
    emit("  DeepLog 的低 FPR 更有營運價值。")

    with open(os.path.join(OUT, "ratio_seq_results.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in log) + "\n")
    with open(os.path.join(OUT, "ratio_seq_summary.json"), "w", encoding="utf-8") as f:
        json.dump(dict(ratios=RATIOS, repeats=REPEATS, n_anom=n_a,
                       n_norm_pool=len(norm), thr_ng=float(thr_ng),
                       thr_dl=float(thr_dl), results=results),
                  f, ensure_ascii=False, indent=2, default=float)
    pd.DataFrame(rows).to_csv(os.path.join(OUT, "ratio_seq.csv"), index=False)
    print(f"\n報告已存: {OUT}/ratio_seq_results.txt")


if __name__ == "__main__":
    main()
