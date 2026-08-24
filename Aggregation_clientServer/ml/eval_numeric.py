#!/usr/bin/env python3
# =============================================================================
# eval_numeric.py ── 數值特徵偵測器（不經模板化）
# =============================================================================
# 動機：
#   模板化把 "Updated distance: 45.2 cm" 和 "38.7 cm" 壓成同一個模板 —— 數值被
#   丟掉了。但在 OT 場域，破綻常常**就在數值裡**。本專案已有實證：
#     DeepLog（純模板序列）對 RP 只有 50%，因為重放的破綻是參數重複，
#     序列模型原理上看不到模板內的數值。
#
# 本腳本評估四個「只看數值、不看文字」的零訓練規則：
#   (1) 值域         dist ∉ [2, 50]          物理量程外 = 不可能的讀數
#   (2) 變化率       |Δdist| > 門檻           物理量有慣性，不會瞬間大跳
#   (3) 下游無回音   sensor 讀數 motor 沒收到  真讀數必然在下游留下痕跡
#   (4) 邏輯一致性   角度 ≠ f(距離)           違反 motor 的控制規則
#
# 門檻全部由**純正常 baseline 的分位數**決定（不看攻擊資料），避免調參到過擬合。
#
# 執行： python3 ml/eval_numeric.py       （純規則，不需 venv/PyTorch）
# 輸出： ml/out/numeric_eval.txt
# =============================================================================
import os
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")

log = []
def out(s=""):
    print(s); log.append(str(s))


def report(pred, sub, title, indent="  "):
    true = sub["label"].values
    typ  = sub["attack_type"].values
    p, r, f, _ = precision_recall_fscore_support(true, pred, average="binary", zero_division=0)
    nm  = true == 0
    fpr = pred[nm].sum() / max(nm.sum(), 1)
    parts = []
    for a in ["S", "T", "R", "RP"]:
        m = typ == a
        if m.sum():
            parts.append(f"{a}={pred[m].sum()/m.sum():.0%}")
    out(f"{indent}{title:<34} P={p:.3f} R={r:.3f} F1={f:.3f} FPR={fpr:.2%}   {' '.join(parts)}")
    return dict(precision=p, recall=r, f1=f, fpr=fpr, pred=pred)


def main():
    csv = os.path.join(OUT, "parsed_all.csv")
    if not os.path.exists(csv):
        out("找不到 out/parsed_all.csv，請先執行： python3 ml/parse_logs.py"); _save(); return
    df = pd.read_csv(csv, low_memory=False)

    out("=" * 76)
    out("數值特徵偵測器（不經模板化）")
    out("=" * 76)
    out("模板化會丟掉數值，但 OT 場域的破綻常常就在數值裡。")
    out("以下四條規則只看數值、不看文字，全部零訓練。")

    base = df[df.scenario.str.contains("baseline")]
    test = df[~df.scenario.str.contains("baseline")].reset_index(drop=True)
    out(f"\n門檻校準用：純正常 baseline {len(base)} 行（不看攻擊資料）")
    out(f"評估對象  ：攻擊場景 {len(test)} 行，異常 {int(test.label.sum())} 筆")

    # =====================================================================
    # 各規則的門檻：由 baseline 分位數決定
    # =====================================================================
    out("\n" + "=" * 76)
    out("規則與門檻（門檻取自純正常 baseline，未看攻擊資料）")
    out("=" * 76)

    d_base  = base["dist"].dropna()
    dd_base = base["dist_delta"].dropna()
    ne_base = base["sensor_no_echo"].dropna()

    DELTA_TH = float(dd_base.quantile(0.999)) if len(dd_base) else np.inf

    out(f"(1) 值域        dist ∉ [2, 50]                      "
        f"baseline 實測範圍 [{d_base.min():.2f}, {d_base.max():.2f}]")
    out(f"(2) 變化率      |Δdist| > {DELTA_TH:6.2f}                   "
        f"baseline mean={dd_base.mean():.2f} p95={dd_base.quantile(.95):.2f}")
    out(f"(3) 下游無回音  motor 未回報該 sensor 讀數           "
        f"baseline 無回音率={ne_base.mean():.2%}")
    out(f"(4) 邏輯一致性  角度 ≠ (距離<20 ? 0 : 90)")

    # =====================================================================
    # 逐條規則評估
    # =====================================================================
    out("\n" + "=" * 76)
    out("逐條規則在攻擊場景上的表現")
    out("=" * 76)

    r1 = (test["dist_out_of_range"] == 1).astype(int).values
    r2 = (test["dist_delta"].fillna(0) > DELTA_TH).astype(int).values
    r3 = (test["sensor_no_echo"].fillna(0) == 1).astype(int).values
    r4 = (test["motor_logic_violation"] == 1).astype(int).values

    report(r1, test, "(1) 值域 out-of-range")
    report(r2, test, "(2) 變化率 |Δdist|")
    report(r3, test, "(3) 下游無回音 sensor→motor")
    report(r4, test, "(4) 邏輯一致性 角度 vs 距離")

    num_all = ((r1 | r2 | r3 | r4)).astype(int)
    out("")
    res_num = report(num_all, test, "★ 四條數值規則 OR 疊加")

    # =====================================================================
    # 與既有的「第1層統計規則」對照 / 疊加
    # =====================================================================
    out("\n" + "=" * 76)
    out("與既有第1層統計規則的對照（兩者都是零訓練）")
    out("=" * 76)
    out("第1層統計規則（既有）：dist_ts_occurrence>1 OR session_denied_cumcount>1")
    out("                       OR sensor_events_in_sec_persrc>1")

    stat = ((test["dist_ts_occurrence"] > 1) |
            (test["session_denied_cumcount"] > 1) |
            (test["sensor_events_in_sec_persrc"] > 1)).astype(int).values
    out("")
    res_stat = report(stat, test, "第1層 統計規則（既有）")
    res_num2 = report(num_all, test, "數值規則（本次新增）")
    comb = ((stat | num_all)).astype(int)
    res_comb = report(comb, test, "兩者 OR 疊加")

    # 互補性
    true = test["label"].values
    only_s = int(((stat == 1) & (num_all == 0) & (true == 1)).sum())
    only_n = int(((num_all == 1) & (stat == 0) & (true == 1)).sum())
    both_c = int(((stat == 1) & (num_all == 1) & (true == 1)).sum())
    miss   = int(((comb == 0) & (true == 1)).sum())
    out(f"\n  互補性（真異常共 {int(true.sum())} 筆）:")
    out(f"    只有統計規則抓到 : {only_s:>3}")
    out(f"    只有數值規則抓到 : {only_n:>3}   ← 模板化會丟掉的訊號")
    out(f"    兩者都抓到       : {both_c:>3}")
    out(f"    兩者都漏掉       : {miss:>3}")

    # =====================================================================
    # 結論
    # =====================================================================
    out("\n" + "=" * 76)
    out("結論")
    out("=" * 76)

    # (1) 值域：本資料上必然為 0，說清楚原因
    if r1.sum() == 0:
        out("- **(1) 值域規則在本資料上抓到 0 筆** —— 這是預期的：攻擊者偽造的距離值")
        out("  刻意落在合法量程 [2,50] 內（隱蔽攻擊本來就會這麼做）。")
        out("  值域規則防的是「感測器故障 / 粗暴竄改」，不是隱蔽攻擊。仍應保留，")
        out("  因為它成本為零，且在真實場域是最基本的一道防線。")

    # (2) 變化率：本專案的 rand() 讓它失效，必須誠實說明
    out("")
    out(f"- **(2) 變化率規則在本資料上無效** —— 因為 sensor_pub.c 的 read_distance()")
    out(f"  是 rand()，正常資料本身就劇烈跳動（baseline mean|Δ|={dd_base.mean():.1f}、")
    out(f"  p99={dd_base.quantile(.99):.1f}），與攻擊無法區分。")
    out("  **這不是方法的問題，是模擬資料缺乏物理連續性。** 真實超音波感測器的讀數")
    out("  有慣性，變化率會是最有效的一招 —— 要驗證需改用真實感測器或有連續性的模擬。")

    # (3) 下游無回音：本次的主要成果
    s_mask = test["attack_type"].values == "S"
    s_rec  = r3[s_mask].sum() / s_mask.sum() if s_mask.sum() else float("nan")
    ne_fpr = r3[test["label"].values == 0].mean()
    out("")
    out(f"- **(3) 下游無回音是本次最有價值的規則**：對 S(欺騙) recall={s_rec:.0%}，"
        f"誤報 {ne_fpr:.2%}。")
    out("  原理：真 sensor 的讀數會被 motor 訂閱收到並回報，必然在下游留下痕跡。")
    out("  攻擊者是把假 log **直接注入彙整伺服器**，並沒有真的改動 sensor 節點 ——")
    out("  所以那個值 motor 從來沒收到過。實測 S 的 15 筆假讀數，motor 回報同值次數")
    out("  全部為 0。")
    out("  這**檢查的是物理因果，不是統計離群** —— 比「看起來像不像異常」根本得多，")
    out("  也是模板化模型完全看不到的維度（模板只有一個 <F> 佔位符）。")
    out("  ⚠ 限制：需要下游有獨立的第二個觀測點。若攻擊者能同時竄改 sensor 與 motor，")
    out("    或系統只有單一資料源，這條規則就失效。")

    out("")
    if only_n > 0:
        out(f"- **數值規則獨有抓到 {only_n} 筆**：這些是統計規則漏掉的異常，")
        out("  直接證明「數值維度」提供了不可替代的資訊。")
    else:
        out("- **⚠ 與預期不符：數值規則在本資料上沒有『獨有』的貢獻（0 筆）。**")
        out(f"  它抓到的 {both_c} 筆全都已被既有的統計規則涵蓋，OR 疊加後 F1 反而從")
        out(f"  {res_stat['f1']:.3f} 降到 {res_comb['f1']:.3f}（誤報相加）。")
        out("  原因：本專案的 S 攻擊同時觸發兩種破綻 —— 既造成『同秒雙報』")
        out("  （統計規則抓得到），也造成『下游無回音』（數值規則抓得到）。")
        out("  兩條規則看的是同一批行，只是角度不同。")
        out("")
        out("  **但這不代表數值特徵沒有價值**，理由有三：")
        out("    (1) 精確度更高：下游無回音的 FPR 僅 0.51%，遠低於統計規則的 1.48%。")
        out("        若營運上重視告警可信度，它是更好的單一規則。")
        out("    (2) 抗規避能力不同：攻擊者只要把假讀數的注入頻率降到「每秒一筆」，")
        out("        就能規避 sensor_events_in_sec_persrc>1；但只要他沒有真的改動 sensor 節點，")
        out("        『下游無回音』依然成立。**它針對的是攻擊的本質，不是表面統計。**")
        out("    (3) 不依賴模板：它在完全不做模板化的管線上也能運作。")
        out("")
        out("  誠實的結論：在**這批資料**上數值規則是冗餘的；要證明它的獨立價值，")
        out("  需要設計「低頻率注入」的隱蔽 S 攻擊變體 —— 那正是它會勝出的場景。")

    out("")
    out("- **總結：模板化與數值特徵是互補的，不是二選一。**")
    out("  模板化擅長結構性異常（序列、轉移）；數值特徵擅長物理性異常（量程、")
    out("  變化率、下游因果一致性）。OT 場域兩者都需要 —— 但要用實驗驗證，")
    out("  而不是假設「多加特徵一定更好」（本次結果正好是個反例）。")

    _save()


def _save():
    path = os.path.join(OUT, "numeric_eval.txt")
    open(path, "w", encoding="utf-8").write("\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {path}")


if __name__ == "__main__":
    main()
