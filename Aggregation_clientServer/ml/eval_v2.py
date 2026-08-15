#!/usr/bin/env python3
# =============================================================================
# eval_v2.py ── 新格式（LogRecord + SourceNode + 真 motor）資料的異常檢測評估
# =============================================================================
# 與舊實驗（EXPERIMENTS.md / RESULTS_SUMMARY.md）的關係：
#   舊資料是「無 SourceNode、且本機無 GPIO 故無 motor」的格式。舊報告據此得到
#   三個核心結論，其中兩個直接受限於那份資料的缺陷：
#     (a) R 的真實 ML recall = 0%（因為 log 無法歸屬來源）
#     (b) sensor_no_echo 這類物理因果特徵幾乎無法評估（多數場景沒有 motor.log）
#
#   本次以新版程式重新採集：aggregation_server 會依 session 身分蓋 SourceNode，
#   且 motor_sub 本機可編譯執行 → 上述兩個缺陷同時消失。本腳本重跑同一套評估，
#   檢驗舊結論在新資料上是否仍然成立。
#
# 本腳本的方法學要求（沿用舊實驗的教訓，不可退步）：
#   1. 一律在「已關閉洩漏管道」的資料上評估（模板洩漏 + dtso 假訊號）。
#      洩漏管道由資料自動偵測，不寫死舊的 template_id。
#   2. 模型比較必須 **多 seed 報 mean ± std**，不可用單次點估計下結論。
#   3. 分攻擊類別報 recall（R 註定低，混在一起會被稀釋看不見）。
#   4. 訓練只用純正常 baseline，攻擊場景完全不參與訓練。
#
# 執行： ml/venv/bin/python ml/eval_v2.py
# 輸出： ml/out/v2_results.txt
# =============================================================================
import os, re, json
import numpy as np
import pandas as pd
import torch, torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import precision_recall_fscore_support, average_precision_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")

WINDOW, HIDDEN, LAYERS, EPOCHS, BATCH, TOPK, LR = 20, 64, 2, 15, 128, 3, 1e-3
SEEDS = [42, 43, 44, 45, 46]
ATTACKS = ["S", "T", "R", "RP"]

log = []
def out(s=""):
    print(s); log.append(str(s))


# =============================================================================
# 資料載入 + 洩漏管道關閉
# =============================================================================
def load(prefix="v2_"):
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"), low_memory=False)
    df = df[df.scenario.str.startswith(prefix)].copy()
    if df.empty:
        raise SystemExit(f"找不到 {prefix}* 場景，請先跑 ml/collect_v2.sh 與 ml/parse_logs.py")
    return df.sort_values(["scenario", "seq_pos"]).reset_index(drop=True)


def close_leaks(df):
    """關閉兩個洩漏管道。管道由資料自動偵測，不寫死舊的 template_id。

    管道1 模板洩漏：只在攻擊行出現、正常行 0 次的模板 → 模型可靠死記蒙對。
      對映到語意最接近的正常 motor 模板（模擬有 GPIO 時它本來就在正常集裡）。
    管道2 dtso 假訊號：偽造的 Motor 行沒有可解析距離值 → dist_ts_occurrence=0，
      而正常 Motor 行都有距離值 → 「Motor 卻沒有距離值」成為 parser 產生的
      攻擊指紋。補正為與正常 Motor 行一致的 1。
    """
    norm = df[df.label == 0]["template_id"].value_counts()
    atk  = df[df.label == 1]["template_id"].value_counts()
    leak_tids = [t for t in atk.index if norm.get(t, 0) == 0]

    # 目標：語意等價的正常 motor 模板（正常集中最常見的 Motor 模板）
    motor_norm = df[(df.label == 0) & (df.source == "Motor")]["template_id"].value_counts()
    target = motor_norm.index[0] if len(motor_norm) else (norm.index[0] if len(norm) else None)

    if leak_tids and target is not None:
        df["template_id"] = df["template_id"].replace({t: target for t in leak_tids})
        fix = df["template_id"].isin([target]) & (df["dist_ts_occurrence"] == 0) & (df.label == 1)
        df.loc[fix, "dist_ts_occurrence"] = 1

    vocab = {t: i for i, t in enumerate(sorted(df["template_id"].unique()))}
    df["tid"] = df["template_id"].map(vocab)
    return df, len(vocab), leak_tids, target


# =============================================================================
# 指標
# =============================================================================
def metrics(pred, sub):
    true = sub["label"].values; typ = sub["attack_type"].values
    p, r, f, _ = precision_recall_fscore_support(true, pred, average="binary", zero_division=0)
    nm = true == 0
    m = dict(precision=p, recall=r, f1=f,
             fpr=float(pred[nm].sum() / max(nm.sum(), 1)))
    for a in ATTACKS:
        k = typ == a
        m[a] = float(pred[k].sum() / k.sum()) if k.sum() else float("nan")
    return m


def show(name, m, indent="  "):
    per = "  ".join(f"{a}={m[a]:.0%}" if m[a] == m[a] else f"{a}=--" for a in ATTACKS)
    out(f"{indent}{name:<32} P={m['precision']:.3f} R={m['recall']:.3f} "
        f"F1={m['f1']:.3f} FPR={m['fpr']:.2%}   {per}")


# =============================================================================
# 偵測器
# =============================================================================
def det_layer1(sub):
    """第1層：跨行統計規則（零訓練）。舊實驗的最佳單一偵測器。"""
    return ((sub["dist_ts_occurrence"].values > 1) |
            (sub["session_denied_cumcount"].values > 1) |
            (sub["sensor_events_in_sec"].values > 1)).astype(int)


def det_sourcenode(sub):
    """SourceNode 規則（零訓練，新格式才有）：伺服器蓋章的來源身分為空 = 匿名寫入。

    這是舊報告指出的「R 的正解」——工程手段而非模型手段。舊資料沒有這個欄位，
    所以這條規則第一次能在完整攻擊資料上被評估。
    """
    # 注意：parse_logs.py 會把 log 裡的 "SourceNode=null" 正規化成字串 "unverified"，
    # 未帶該欄位的舊格式行則為 NaN。NaN 是「這份 log 沒有這個欄位」而非「匿名寫入」，
    # 不可判為異常，否則舊格式資料會全部被誤報。
    sn = sub["lr_SourceNode"].astype(str).str.strip().str.lower()
    return sn.isin(["unverified", "null", "none"]).astype(int)


def det_no_echo(sub):
    """物理因果規則（零訓練）：sensor 讀數在下游 motor 沒有回音。

    真讀數會被 motor 訂閱收到並回報；攻擊者把假 log 直接注入彙整伺服器，
    並沒有真的改動 sensor 節點 → 那個值 motor 從來沒收到過。
    需要 motor 資料才能判定，舊資料多數場景缺 motor.log。
    """
    return (sub["sensor_no_echo"].fillna(0).values > 0).astype(int)


# ---- 第2層 DeepLog ----
class DeepLog(nn.Module):
    def __init__(s, V, h, l):
        super().__init__()
        s.emb = nn.Embedding(V, h); s.lstm = nn.LSTM(h, h, l, batch_first=True); s.fc = nn.Linear(h, V)
    def forward(s, x):
        o, _ = s.lstm(s.emb(x)); return s.fc(o[:, -1, :])


def windows(seq, w=WINDOW):
    X, y, idx = [], [], []
    for i in range(len(seq) - w):
        X.append(seq[i:i+w]); y.append(seq[i+w]); idx.append(i+w)
    return np.array(X), np.array(y), np.array(idx)


def train_deeplog(df, V, seed):
    torch.manual_seed(seed); np.random.seed(seed)
    base = df[df.scenario.str.contains("baseline")]
    Xs, ys = [], []
    for s in base.scenario.unique():
        seq = base[base.scenario == s].sort_values("seq_pos")["tid"].values
        X, y, _ = windows(seq)
        if len(X): Xs.append(X); ys.append(y)
    if not Xs:
        raise SystemExit("baseline 場景不足以訓練 DeepLog")
    X, y = np.concatenate(Xs), np.concatenate(ys)
    model = DeepLog(V, HIDDEN, LAYERS)
    opt = torch.optim.Adam(model.parameters(), lr=LR); lf = nn.CrossEntropyLoss()
    dl = DataLoader(TensorDataset(torch.tensor(X), torch.tensor(y)), batch_size=BATCH, shuffle=True)
    model.train()
    for _ in range(EPOCHS):
        for xb, yb in dl:
            opt.zero_grad(); lf(model(xb), yb).backward(); opt.step()
    model.eval()
    return model


def deeplog_scores(model, sub):
    """回傳 (top-k 判定, rank 連續分數)。rank 供 PR-AUC，不受單一 k 影響。"""
    pred = np.zeros(len(sub), dtype=int)
    rank = np.zeros(len(sub), dtype=float)
    for s in sub.scenario.unique():
        m = (sub.scenario == s).values
        part = sub[m].sort_values("seq_pos")
        X, y, idx = windows(part["tid"].values)
        if len(X) == 0: continue
        with torch.no_grad():
            logits = model(torch.tensor(X))
        order = torch.argsort(logits, dim=1, descending=True).numpy()
        rk = np.array([int(np.where(order[i] == y[i])[0][0]) for i in range(len(y))])
        pos = np.where(m)[0]
        pred[pos[idx]] = (rk >= TOPK).astype(int)
        rank[pos[idx]] = rk
    return pred, rank


# =============================================================================
# 主流程
# =============================================================================
def main():
    df = load()
    df, V, leak_tids, leak_target = close_leaks(df)

    base_scen = sorted(s for s in df.scenario.unique() if "baseline" in s)
    atk_scen  = sorted(s for s in df.scenario.unique() if "baseline" not in s)
    test = df[df.scenario.isin(atk_scen)].sort_values(["scenario", "seq_pos"]).reset_index(drop=True)

    out("=" * 78)
    out("新格式資料（LogRecord + SourceNode + 真 motor）異常檢測評估")
    out("=" * 78)
    out(f"總行數      : {len(df)}   異常 {int(df.label.sum())} "
        f"({df.label.mean():.2%})")
    out(f"baseline    : {len(base_scen)} 場景 / {len(df[df.scenario.isin(base_scen)])} 行（只用於訓練）")
    out(f"攻擊場景    : {len(atk_scen)} 場景 / {len(test)} 行 / {int(test.label.sum())} 異常")
    out(f"異常組成    : {test[test.label==1].attack_type.value_counts().to_dict()}")
    n_motor = int((df.source == 'Motor').sum())
    out(f"motor 行數  : {n_motor}   ← 舊實驗多數場景為 0（本機無 GPIO）")
    out()
    out(f"洩漏管道關閉: 攻擊專屬模板 {leak_tids} → {leak_target}，並補正其 dtso")
    out(f"模板詞彙量  : V={V}")

    # -----------------------------------------------------------------------
    # 零訓練規則
    # -----------------------------------------------------------------------
    out("\n" + "=" * 78)
    out("一、零訓練規則偵測器")
    out("=" * 78)
    l1 = det_layer1(test)
    sn = det_sourcenode(test)
    ne = det_no_echo(test)
    m_l1, m_sn, m_ne = metrics(l1, test), metrics(sn, test), metrics(ne, test)
    show("第1層 跨行統計規則", m_l1)
    show("SourceNode==null（新）", m_sn)
    show("sensor_no_echo 物理因果（新）", m_ne)

    l1_sn = ((l1 == 1) | (sn == 1)).astype(int)
    l1_sn_ne = ((l1 == 1) | (sn == 1) | (ne == 1)).astype(int)
    m_l1sn = metrics(l1_sn, test)
    m_all3 = metrics(l1_sn_ne, test)
    show("統計 OR SourceNode", m_l1sn)
    show("統計 OR SourceNode OR no_echo", m_all3)

    # -----------------------------------------------------------------------
    # DeepLog 多 seed
    # -----------------------------------------------------------------------
    out("\n" + "=" * 78)
    out(f"二、第2層 DeepLog 序列模型（{len(SEEDS)} seeds, window={WINDOW}, hidden={HIDDEN}, k={TOPK}）")
    out("=" * 78)
    runs, prauc, dl_preds = [], [], []
    for sd in SEEDS:
        model = train_deeplog(df, V, sd)
        pred, rank = deeplog_scores(model, test)
        mm = metrics(pred, test)
        runs.append(mm); dl_preds.append(pred)
        prauc.append(average_precision_score(test["label"].values, rank))
        show(f"seed={sd}", mm)

    def ms(key, vals=None):
        v = np.array(vals if vals is not None else [r[key] for r in runs], dtype=float)
        v = v[~np.isnan(v)]
        return (v.mean(), v.std()) if len(v) else (float("nan"), float("nan"))

    out("\n  多 seed 統計（mean ± std）:")
    out(f"    {'PR-AUC':<12} {ms('', prauc)[0]:.3f} ± {ms('', prauc)[1]:.3f}")
    for k in ["precision", "recall", "f1", "fpr"]:
        mu, sd_ = ms(k)
        out(f"    {k:<12} {mu:.3f} ± {sd_:.3f}")
    for a in ATTACKS:
        mu, sd_ = ms(a)
        out(f"    {a+' recall':<12} {mu:.3f} ± {sd_:.3f}")

    # 用中位數表現的 seed 當代表，做疊加分析
    f1s = [r["f1"] for r in runs]
    rep = int(np.argsort(f1s)[len(f1s) // 2])
    dl = dl_preds[rep]
    out(f"\n  以中位 F1 的 seed={SEEDS[rep]} 作為疊加分析代表")

    # -----------------------------------------------------------------------
    # 疊加
    # -----------------------------------------------------------------------
    out("\n" + "=" * 78)
    out("三、疊加：規則 × DeepLog")
    out("=" * 78)
    or_  = ((l1 == 1) | (dl == 1)).astype(int)
    and_ = ((l1 == 1) & (dl == 1)).astype(int)
    m_dl, m_or, m_and = metrics(dl, test), metrics(or_, test), metrics(and_, test)
    show("第1層 統計規則", m_l1)
    show("第2層 DeepLog", m_dl)
    show("OR（任一層報警）", m_or)
    show("AND（兩層都報警）", m_and)
    best = ((l1 == 1) | (sn == 1) | (dl == 1)).astype(int)
    m_best = metrics(best, test)
    show("統計 OR SourceNode OR DeepLog", m_best)

    # 互補性
    true = test["label"].values
    out(f"\n  互補性（真異常 {int(true.sum())} 筆）:")
    out(f"    只有第1層抓到     : {int(((l1==1)&(dl==0)&(true==1)).sum()):>3}")
    out(f"    只有DeepLog抓到   : {int(((dl==1)&(l1==0)&(true==1)).sum()):>3}")
    out(f"    兩層都抓到        : {int(((l1==1)&(dl==1)&(true==1)).sum()):>3}")
    out(f"    兩層都漏掉        : {int(((l1==0)&(dl==0)&(true==1)).sum()):>3}")
    out(f"    其中 SourceNode 救回 : "
        f"{int(((l1==0)&(dl==0)&(sn==1)&(true==1)).sum()):>3}  ← 兩層都漏、但規則抓到")

    # -----------------------------------------------------------------------
    # 逐場景
    # -----------------------------------------------------------------------
    out("\n" + "=" * 78)
    out("四、逐場景結果（最佳組合：統計 OR SourceNode OR DeepLog）")
    out("=" * 78)
    for s in atk_scen:
        m = (test.scenario == s).values
        if m.sum() == 0: continue
        mm = metrics(best[m], test[m].reset_index(drop=True))
        show(s[:30], mm)

    # -----------------------------------------------------------------------
    # 摘要 JSON（供報告與繪圖引用，避免手抄數字）
    # -----------------------------------------------------------------------
    # 互補性以「實際逐行交集」計數，而非由 recall 反推（反推在四捨五入下會失真）
    t_mask = test["label"].values == 1
    overlap = dict(
        total=int(t_mask.sum()),
        l1_only=int(((l1 == 1) & (sn == 0) & t_mask).sum()),
        both=int(((l1 == 1) & (sn == 1) & t_mask).sum()),
        sn_only=int(((sn == 1) & (l1 == 0) & t_mask).sum()),
        missed=int(((l1 == 0) & (sn == 0) & t_mask).sum()),
    )
    for k, m in [("l1_only", (l1 == 1) & (sn == 0)), ("both", (l1 == 1) & (sn == 1)),
                 ("sn_only", (sn == 1) & (l1 == 0)), ("missed", (l1 == 0) & (sn == 0))]:
        overlap[k + "_types"] = test[m & t_mask].attack_type.value_counts().to_dict()

    summary = dict(
        n_rows=int(len(df)), n_anom=int(df.label.sum()),
        anom_rate=float(df.label.mean()),
        n_test=int(len(test)), n_test_anom=int(test.label.sum()),
        composition=test[test.label == 1].attack_type.value_counts().to_dict(),
        n_motor_rows=n_motor, vocab=int(V), leak_tids=list(leak_tids),
        scenarios=dict(baseline=base_scen, attack=atk_scen),
        detectors=dict(layer1=m_l1, sourcenode=m_sn, no_echo=m_ne,
                       l1_or_sn=m_l1sn, l1_or_sn_or_ne=m_all3,
                       deeplog=m_dl, hybrid_or=m_or, hybrid_and=m_and, best=m_best),
        deeplog_seeds=dict(seeds=SEEDS, runs=runs, prauc=prauc,
                           prauc_mean=float(np.mean(prauc)), prauc_std=float(np.std(prauc))),
        overlap=overlap,
    )
    with open(os.path.join(OUT, "v2_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=float)

    with open(os.path.join(OUT, "v2_results.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {OUT}/v2_results.txt")
    print(f"摘要已存: {OUT}/v2_summary.json")


if __name__ == "__main__":
    main()
