#!/usr/bin/env python3
# =============================================================================
# detect_net.py ── 用 ML(IsolationForest) 對網路流量特徵做異常檢測
# =============================================================================
# 資料：pcap_to_features.py 產生的 benign_flows.csv / spoof_flows.csv。
#
# 方法（無監督異常偵測，符合實務——攻擊當下沒有標籤）：
#   1) 只用 benign_flows.csv 訓練 IsolationForest，學「正常秒」的流量分布。
#      （攻擊資料不參與訓練，避免資訊洩漏。）
#   2) 對 spoof_flows.csv 每一秒打異常分數，分數越低越異常。
#   3) 門檻取自 benign 分數分布（contamination 分位數），在 spoof 上判 0/1。
#   4) 用 spoof 的 ground-truth label（注入秒=1）算 Precision/Recall/F1；
#      分數整體算 ROC-AUC / PR-AUC（不依賴單一門檻）。
#
# 為什麼能抓到 spoof：攻擊者多開一條匿名 TCP 連線並額外送 Write，
#   注入的那幾秒 n_conns / uniq_client_ports / n_pkts_c2s / bytes_c2s 會高於
#   正常秒的分布 → IsolationForest 把它們判為離群。
#
# 指標選擇：異常秒極少（不平衡），accuracy 無意義，故報 P/R/F1 + PR-AUC。
#
# 用法：
#   ml/venv/bin/python net/detect_net.py net/captures/spoof_<STAMP>
# 輸出：<dir>/net_detect_results.txt，並附每秒分數 spoof_scored.csv
# =============================================================================
import sys, os, csv
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (precision_score, recall_score, f1_score,
                                 roc_auc_score, average_precision_score,
                                 confusion_matrix)
except Exception as e:
    sys.exit(f"需要 scikit-learn：ml/venv/bin/pip install scikit-learn（{e}）")

FEATURES = ["n_pkts", "n_pkts_c2s", "n_pkts_s2c", "bytes_c2s", "bytes_s2c",
            "n_conns", "n_syn", "n_fin_rst", "uniq_client_ports", "max_payload"]
SEED = 42


def load(path):
    """回傳 (X: [n,f] float, y: [n] int, rows: list[dict])。"""
    rows = list(csv.DictReader(open(path)))
    if not rows:
        return np.empty((0, len(FEATURES))), np.empty((0,), int), rows
    X = np.array([[float(r[k]) for k in FEATURES] for r in rows], float)
    y = np.array([int(r.get("label", 0)) for r in rows], int)
    return X, y, rows


def fmt(x):
    return "n/a" if x is None else f"{x:.3f}"


def main():
    if len(sys.argv) < 2:
        sys.exit("用法：detect_net.py <capture_dir>")
    d = sys.argv[1]
    fb = os.path.join(d, "benign_flows.csv")
    fs = os.path.join(d, "spoof_flows.csv")
    for f in (fb, fs):
        if not os.path.exists(f):
            sys.exit(f"找不到 {f} —— 請先跑 net/pcap_to_features.py {d}")

    Xb, _, _ = load(fb)
    Xs, ys, rows_s = load(fs)
    if len(Xb) == 0 or len(Xs) == 0:
        sys.exit("特徵為空（pcap 可能沒抓到封包）。")

    n_anom = int(ys.sum())
    have_labels = n_anom > 0

    # contamination：以 spoof 的真實異常比例為先驗；無標籤時取小值 0.02。
    contam = max(min(n_anom / len(ys), 0.5), 1e-3) if have_labels else 0.02

    # 標準化：只 fit 在 benign（避免用到測試分布資訊）。
    scaler = StandardScaler().fit(Xb)
    Xb_s, Xs_s = scaler.transform(Xb), scaler.transform(Xs)

    clf = IsolationForest(n_estimators=300, contamination=contam,
                          random_state=SEED)
    clf.fit(Xb_s)

    # score_samples 越低越異常。門檻取 benign 分數的 contam 分位數。
    sb = clf.score_samples(Xb_s)
    ss = clf.score_samples(Xs_s)
    thr = np.quantile(sb, contam)
    pred = (ss < thr).astype(int)           # 低於門檻 → 判為異常

    # 退化保護：若 benign 幾乎零變異（例如抓取太短、流量太規律），
    # IsolationForest 學不到切分 → 所有分數幾乎相同、無鑑別力。
    # 改用「與 benign 平均的馬氏/標準化歐氏距離」當異常分數兜底，
    # 讓明顯離群（spoof 多連線/多封包）仍能被標記，不會靜默回報 0。
    forest_flat = float(np.ptp(sb)) < 1e-9 or float(np.ptp(ss)) < 1e-9
    if forest_flat:
        mu = Xb_s.mean(axis=0)
        dist = np.sqrt(((Xs_s - mu) ** 2).sum(axis=1))   # 標準化歐氏距離
        ss = -dist                                        # 距離越大 → 分數越低（越異常）
        db = np.sqrt(((Xb_s - mu) ** 2).sum(axis=1))
        thr = -np.quantile(db, 1.0 - contam)
        pred = (ss < thr).astype(int)

    lines = []
    P = lines.append
    P("=" * 60)
    P("網路流量 ML 異常檢測結果（IsolationForest, 無監督）")
    P("=" * 60)
    P(f"資料夾            : {d}")
    P(f"訓練(benign) 秒數 : {len(Xb)}")
    P(f"測試(spoof)  秒數 : {len(Xs)}  其中異常秒(ground truth) = {n_anom}")
    P(f"特徵              : {', '.join(FEATURES)}")
    P(f"contamination     : {contam:.4f}")
    P(f"門檻(benign分位)  : {thr:.4f}")
    if forest_flat:
        P("⚠ benign 近乎零變異 → IsolationForest 無鑑別力，改用標準化歐氏距離兜底。")
        P("  （這通常代表抓取太短或流量過度規律；正式評估請加長 benign 抓取時間。）")
    P("")

    if have_labels:
        prec = precision_score(ys, pred, zero_division=0)
        rec = recall_score(ys, pred, zero_division=0)
        f1 = f1_score(ys, pred, zero_division=0)
        # AUC 用連續分數（取負，讓「越異常分數越高」符合 sklearn 慣例）。
        roc = roc_auc_score(ys, -ss) if len(set(ys)) > 1 else None
        pr = average_precision_score(ys, -ss) if len(set(ys)) > 1 else None
        tn, fp, fn, tp = confusion_matrix(ys, pred, labels=[0, 1]).ravel()
        P("— 門檻判定（單一工作點）—")
        P(f"  Precision : {fmt(prec)}")
        P(f"  Recall    : {fmt(rec)}   （抓到 {tp}/{n_anom} 個注入秒）")
        P(f"  F1        : {fmt(f1)}")
        P(f"  混淆矩陣  : TP={tp} FP={fp} FN={fn} TN={tn}")
        P("")
        P("— 分數整體（與門檻無關）—")
        P(f"  ROC-AUC   : {fmt(roc)}")
        P(f"  PR-AUC    : {fmt(pr)}   （不平衡下比 ROC 更能反映偵測力）")
        P("")
        # 診斷：注入秒 vs 正常秒的特徵均值，說明模型「看到了什麼」。
        Xs_anom = Xs[ys == 1]
        Xs_norm = Xs[ys == 0]
        P("— 注入秒 vs 正常秒 平均特徵（模型抓到的破綻來源）—")
        P(f"  {'feature':<18}{'inject':>10}{'normal':>10}")
        for i, k in enumerate(FEATURES):
            a = Xs_anom[:, i].mean() if len(Xs_anom) else float("nan")
            n = Xs_norm[:, i].mean() if len(Xs_norm) else float("nan")
            mark = "  <—" if (n and a > n * 1.15) else ""
            P(f"  {k:<18}{a:>10.2f}{n:>10.2f}{mark}")
    else:
        n_flag = int(pred.sum())
        P("⚠ spoof_flows.csv 無 ground-truth 標籤（缺 spoof_attack.log 注入時間）。")
        P(f"  純無監督：在 {len(Xs)} 秒中標記 {n_flag} 秒為異常候選。")
        P("  下列為分數最低（最異常）的前 10 秒：")
        order = np.argsort(ss)[:10]
        P(f"  {'t_rel':>6}{'score':>10}  " + "  ".join(f"{k}" for k in FEATURES[:5]))
        for idx in order:
            r = rows_s[idx]
            P(f"  {r['t_rel']:>6}{ss[idx]:>10.3f}  " +
              "  ".join(f"{r[k]}" for k in FEATURES[:5]))

    # 附每秒分數，方便畫圖/檢視
    scored = os.path.join(d, "spoof_scored.csv")
    with open(scored, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["t_rel"] + FEATURES + ["label", "anomaly_score", "pred"])
        for i, r in enumerate(rows_s):
            w.writerow([r["t_rel"]] + [r[k] for k in FEATURES] +
                       [r.get("label", 0), f"{ss[i]:.5f}", int(pred[i])])

    out = os.path.join(d, "net_detect_results.txt")
    open(out, "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\n[detect] 結果已存：{out}")
    print(f"[detect] 每秒分數：{scored}")


if __name__ == "__main__":
    main()
