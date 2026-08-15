#!/usr/bin/env python3
# =============================================================================
# eval_sourcenode.py ── 對照實驗：有 SourceNode vs 無 SourceNode
# =============================================================================
# 本專案的核心結論是「R(否認)攻擊不該用 ML 解」。ablation_leakage.py 已證明前半段
# （三個 ML 模型的真實 R recall 都是 0%）；本腳本補上後半段：
#
#   用對的工程手段（OPC UA Part 22 LogRecord 的 SourceNode，由伺服器依 session
#   身分蓋章），R 用「一條規則」就能偵測。
#
# 對照設計：
#   條件 A（無 SourceNode）：既有舊格式資料 —— ML 模型的最佳表現，R recall = 0%
#   條件 B（有 SourceNode）：新採集資料 —— 規則 `SourceNode == null` 判為異常
#
# 為什麼這個對照是公平的：
#   兩邊都在偵測「同一種攻擊」（repudiation_attack 產生的偽造 motor log），
#   差別只在「log 裡有沒有來源歸屬欄位」。這正好隔離出本研究要證明的變因。
#
# 執行： python3 ml/eval_sourcenode.py     （純規則，不需要 venv/PyTorch）
# 輸出： ml/out/sourcenode_eval.txt
# =============================================================================
import os
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")

log = []
def out(s=""):
    print(s); log.append(str(s))


def main():
    csv = os.path.join(OUT, "parsed_all.csv")
    if not os.path.exists(csv):
        out("找不到 out/parsed_all.csv，請先執行： python3 ml/parse_logs.py")
        return
    df = pd.read_csv(csv, low_memory=False)

    out("=" * 72)
    out("對照實驗：有 SourceNode vs 無 SourceNode（R 否認攻擊）")
    out("=" * 72)

    # 新格式 = 有 lr_SourceNode 欄位值的行
    if "lr_SourceNode" not in df.columns:
        out("parsed_all.csv 沒有 lr_SourceNode 欄位 —— 請更新 ml/parse_logs.py 後重跑。")
        _save(); return

    new = df[df["lr_SourceNode"].notna()].copy()
    old = df[df["lr_SourceNode"].isna()].copy()

    out(f"\n資料組成：")
    out(f"  舊格式（無 SourceNode）: {len(old):>6} 行   來自既有採集")
    out(f"  新格式（有 SourceNode）: {len(new):>6} 行   來自 ml/collect_sourcenode.sh")

    if len(new) == 0:
        out("")
        out("=" * 72)
        out("尚未採集新格式資料")
        out("=" * 72)
        out("本腳本需要含 SourceNode 的 log 才能做對照。請先執行：")
        out("")
        out("    ./ml/collect_sourcenode.sh quick     # 先跑快速驗證（約 5 分鐘）")
        out("    ./ml/collect_sourcenode.sh 30        # 正式採集（約 40 分鐘）")
        out("    python3 ml/parse_logs.py             # 重新解析")
        out("    python3 ml/eval_sourcenode.py        # 再跑本腳本")
        out("")
        out("條件 A（無 SourceNode）的基準結果已在 out/ablation_leakage.txt：")
        out("  IsolationForest / RandomForest / DeepLog 的真實 R recall 皆為 0%。")
        _save(); return

    # =====================================================================
    # 條件 B：規則偵測 SourceNode == null
    # =====================================================================
    out("\n" + "=" * 72)
    out("條件 B：有 SourceNode —— 規則「SourceNode 未驗證 → 異常」")
    out("=" * 72)

    scen_list = sorted(new["scenario"].unique())
    out(f"新格式場景：{scen_list}")

    out("\nSourceNode 分布：")
    for node, cnt in new["lr_SourceNode"].value_counts().items():
        tag = "未驗證（匿名寫入）" if node == "unverified" else "已驗證"
        out(f"  {str(node):<30} {cnt:>6} 行   {tag}")

    # 規則：來源未驗證即異常
    pred = (new["lr_SourceNode"] == "unverified").astype(int).values
    true = new["label"].values
    typ  = new["attack_type"].values

    p, r, f, _ = precision_recall_fscore_support(true, pred, average="binary", zero_division=0)
    out(f"\n整體  precision={p:.3f}  recall={r:.3f}  f1={f:.3f}")
    out("混淆矩陣 [列=真實(正常,異常), 欄=預測]:")
    out(confusion_matrix(true, pred))

    out("\n各攻擊類別 recall：")
    for a in ["S", "T", "R", "RP"]:
        m = typ == a
        if m.sum() == 0: continue
        out(f"  [{a}] {int(pred[m].sum())}/{int(m.sum())} = {pred[m].sum()/m.sum():.0%}")

    nm = true == 0
    fpr = pred[nm].sum() / max(nm.sum(), 1)
    out(f"\n正常誤報 FPR = {int(pred[nm].sum())}/{int(nm.sum())} = {fpr:.2%}")

    # =====================================================================
    # 對照表
    # =====================================================================
    r_mask = typ == "R"
    r_recall = pred[r_mask].sum() / r_mask.sum() if r_mask.sum() else float("nan")

    out("\n" + "=" * 72)
    out("對照：R(否認) 攻擊的偵測能力")
    out("=" * 72)
    out(f"{'條件':<34} {'方法':<26} {'R recall':>9}")
    out("-" * 72)
    out(f"{'A. 無 SourceNode（舊格式）':<30} {'IsolationForest':<26} {'0%':>9}")
    out(f"{'':<30} {'RandomForest':<26} {'0%':>9}")
    out(f"{'':<30} {'DeepLog (LSTM)':<26} {'0%':>9}")
    out("-" * 72)
    out(f"{'B. 有 SourceNode（新格式）':<30} {'規則 SourceNode 未驗證':<26} {r_recall:>8.0%}")
    out("-" * 72)

    out("\n" + "=" * 72)
    out("結論")
    out("=" * 72)
    if r_mask.sum() == 0:
        out("- 新格式資料中沒有標記為 R 的行，無法計算 R recall。")
        out("  請確認 collect_sourcenode.sh 有跑到 R_only 場景且標記正確。")
    elif r_recall >= 0.99:
        out("- **R 從「三個 ML 模型 recall 全部 0%」變成「一條規則 100%」。**")
        out("- 這不是模型變強了，而是『資料裡終於有了可歸屬來源的欄位』。")
        out("  攻擊者能逐字複製 log 內容，卻無法冒用 session 身分 —— SourceNode 由")
        out("  伺服器蓋章，是攻擊者唯一無法偽造的東西。")
        out("- 對應規範：OPC UA Part 22 (Diagnostics) Table 8 早已定義 SourceNode")
        out("  (0:NodeId)，並註明『若記錄不屬於特定 Node 則設為 null』。匿名寫入者")
        out("  確實不對應任何已知 Node —— 填 null 完全符合規範語意。")
        out("- **本研究最實際的產出**：先用實驗證明某個問題不該用 ML 解，")
        out("  再用對的工程手段解掉它。")
    else:
        out(f"- 規則的 R recall 為 {r_recall:.0%}，未達預期的 100%。可能原因：")
        out("  (1) 部分 R 行的標記有誤（檢查 anomaly_marked.log）")
        out("  (2) 攻擊者的連線被誤判為已授權（檢查 aggregation_server 的 SOURCE_REGISTRY）")

    # T 的 recall 預期就是 0%，這不是缺陷 —— 說清楚以免被誤讀
    t_mask = typ == "T"
    if t_mask.sum() and pred[t_mask].sum() == 0:
        out("")
        out("- **T(竄改) 的 0% 是預期內的，不是這個規則的缺陷**：T 的行是伺服器對")
        out("  『寫入被拒』所產生的回應（BadUserAccessDenied），由伺服器自己記錄、")
        out("  來源本來就是已驗證的；攻擊者並沒有『注入一行假 log』。")
        out("  → SourceNode 這條規則專治『偽造來源』類攻擊（R，以及順帶抓到 S/RP 的")
        out("    注入行）。T 仍應交給第2層 DeepLog（實測 recall 1.000 ± 0.000）。")
        out("  這正好呼應本研究的核心結論：**沒有單一手段通吃，要按破綻的性質選工具。**")

    if fpr > 0:
        out(f"\n- 注意 FPR={fpr:.2%}：有正常行也被標成未驗證來源。")
        out("  常見原因是某個正常 client 沒有設定具名 session（檢查 sessionName 設定），")
        out("  或伺服器自身寫入不帶 session。這類行應加入 SOURCE_REGISTRY 或另行豁免。")
    else:
        out(f"\n- **FPR = 0.00%**：沒有任何正常行被誤判。因為所有正常 client 都以具名")
        out("  session 連線，來源一律可驗證 —— 這是身分綁定相對於統計方法的根本優勢：")
        out("  它判斷的是『可驗證的事實』，不是『看起來像不像異常』。")

    _save()


def _save():
    path = os.path.join(OUT, "sourcenode_eval.txt")
    open(path, "w", encoding="utf-8").write("\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {path}")


if __name__ == "__main__":
    main()
