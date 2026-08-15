#!/usr/bin/env python3
# =============================================================================
# make_figures_v2.py ── 新格式實驗（EXPERIMENTS_V2.md）的圖表
# =============================================================================
# 數據來源：ml/out/v2_summary.json（由 eval_v2.py 產生）。
#   刻意「讀 JSON 而不是寫死常數」—— 舊版 make_figures.py 把數字硬編在程式裡，
#   一旦重跑實驗就可能與報告不同步。這裡改成單一事實來源。
#
# 設計原則沿用舊版：不用雙 y 軸、色盲安全配色、直接標數值、淺色列印友善。
#
# 執行： ml/venv/bin/python ml/make_figures_v2.py
# =============================================================================
import os, json, logging
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
FIG  = os.path.join(HERE, "figures")
OUT  = os.path.join(HERE, "out")
os.makedirs(FIG, exist_ok=True)

FONT_PATH = os.path.join(HERE, "assets", "NotoSansTC.ttf")
if os.path.exists(FONT_PATH):
    fm.fontManager.addfont(FONT_PATH)
    plt.rcParams["font.family"] = fm.FontProperties(fname=FONT_PATH).get_name()
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
plt.rcParams["axes.unicode_minus"] = False

BLUE, ORANGE, GREEN = "#2a78d6", "#eb6834", "#1baf7a"
RED, GREY = "#d03b3b", "#898781"
INK, SUB  = "#0b0b0b", "#52514e"
GRID      = "#e1e0d9"
DPI = 160

S = json.load(open(os.path.join(OUT, "v2_summary.json"), encoding="utf-8"))
D = S["detectors"]


def style(ax, xlabel=None, ylabel=None, title=None, sub=None, grid_axis="x"):
    for s in ("top", "right", "left" if grid_axis == "x" else "bottom"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom" if grid_axis == "x" else "left"].set_color("#c3c2b7")
    ax.grid(axis=grid_axis, color=GRID, lw=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(colors=SUB, labelsize=9.5, length=0)
    if xlabel: ax.set_xlabel(xlabel, fontsize=10, color=SUB)
    if ylabel: ax.set_ylabel(ylabel, fontsize=10, color=SUB)
    if title:
        ax.set_title(title, fontsize=13, color=INK, loc="left", pad=18 if sub else 10)
    if sub:
        ax.text(0, 1.02, sub, transform=ax.transAxes, fontsize=9.5, color=SUB, va="bottom")


def save(fig, name):
    fig.savefig(os.path.join(FIG, name), dpi=DPI, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ figures/{name}")


# =============================================================================
# 圖 V1：偵測器對照（F1 / Recall / FPR）
# =============================================================================
def fig_detectors():
    names = ["第1層\n統計規則", "SourceNode\n==null", "sensor_no_echo\n物理因果",
             "第2層\nDeepLog", "統計 OR\nSourceNode"]
    keys  = ["layer1", "sourcenode", "no_echo", "deeplog", "l1_or_sn"]
    f1  = [D[k]["f1"] for k in keys]
    rc  = [D[k]["recall"] for k in keys]
    fpr = [D[k]["fpr"] * 100 for k in keys]

    fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.2))
    for ax, vals, ttl, color, fmt in [
        (axes[0], f1,  "F1（越高越好）",      BLUE,   "{:.3f}"),
        (axes[1], rc,  "Recall（越高越好）",  GREEN,  "{:.0%}"),
        (axes[2], fpr, "FPR %（越低越好）",   ORANGE, "{:.2f}%"),
    ]:
        bars = ax.bar(range(len(names)), vals, color=color, zorder=3, width=0.62)
        # 最佳者以深色強調
        best = int(np.argmax(vals)) if ttl.startswith(("F1", "Recall")) else int(np.argmin(vals))
        bars[best].set_color(INK)
        for i, v in enumerate(vals):
            ax.text(i, v + max(vals) * 0.03, fmt.format(v), ha="center",
                    fontsize=9.5, color=INK,
                    fontweight="bold" if i == best else "normal")
        ax.set_xticks(range(len(names)))
        # 標籤較長，稍微旋轉避免相鄰標籤互相重疊
        ax.set_xticklabels(names, fontsize=8.5, rotation=18, ha="right")
        ax.set_ylim(0, max(vals) * 1.22 if max(vals) > 0 else 1)
        style(ax, title=ttl, grid_axis="y")
    # 標題與子標題都用 fig.text（不用 suptitle）：tight_layout 會移動 suptitle
    # 但不會移動 fig.text，兩者混用就會疊在一起。
    fig.tight_layout(rect=[0, 0, 1, 0.88])
    fig.text(0.005, 0.975, "偵測器對照 —— SourceNode 規則以零誤報取得最高 F1",
             fontsize=14, color=INK, ha="left", va="top")
    fig.text(0.005, 0.915,
             f"深色 = 該指標最佳 · 測試集 {S['n_test']} 行 / {S['n_test_anom']} 異常",
             fontsize=9.5, color=SUB, ha="left", va="top")
    save(fig, "v2_fig1_detectors.png")


# =============================================================================
# 圖 V2：分攻擊類別 recall —— R 的變化是重點
# =============================================================================
def fig_per_attack():
    atk = ["S", "T", "R", "RP"]
    keys = [("layer1", "第1層 統計規則", BLUE),
            ("sourcenode", "SourceNode==null", GREEN),
            ("deeplog", "第2層 DeepLog", GREY),
            ("l1_or_sn", "統計 OR SourceNode", INK)]
    fig, ax = plt.subplots(figsize=(10, 4.4))
    n = len(keys); w = 0.8 / n
    for j, (k, lbl, c) in enumerate(keys):
        vals = [D[k].get(a, 0) or 0 for a in atk]
        xs = np.arange(len(atk)) + (j - (n - 1) / 2) * w
        ax.bar(xs, vals, width=w * 0.92, color=c, label=lbl, zorder=3)
        for x, v in zip(xs, vals):
            if v > 0.02:
                ax.text(x, v + 0.03, f"{v:.0%}", ha="center", fontsize=8, color=INK)
    ax.set_xticks(range(len(atk)))
    ax.set_xticklabels([f"{a}\n(n={S['composition'].get(a, 0)})" for a in atk], fontsize=10)
    ax.set_ylim(0, 1.18)
    ax.set_yticks([0, .25, .5, .75, 1])
    ax.set_yticklabels(["0%", "25%", "50%", "75%", "100%"])
    style(ax, ylabel="recall", grid_axis="y",
          title="分攻擊類別 recall —— R 從舊實驗的 0% 變成 100%",
          sub="R 只有 SourceNode 抓得到；T 只有統計規則抓得到 —— 兩者互補，不可互相取代")
    # 圖例置於標題與子標題之下，避免蓋住文字
    ax.legend(loc="upper center", ncol=4, frameon=False, fontsize=9,
              bbox_to_anchor=(0.5, 1.30))
    save(fig, "v2_fig2_per_attack.png")


# =============================================================================
# 圖 V3：DeepLog 的 seed 不穩定性
# =============================================================================
def fig_seeds():
    runs = S["deeplog_seeds"]["runs"]; seeds = S["deeplog_seeds"]["seeds"]
    f1 = [r["f1"] for r in runs]
    fig, ax = plt.subplots(figsize=(9.5, 4))
    bars = ax.bar([str(s) for s in seeds], f1, color=GREY, zorder=3, width=0.55)
    for i, v in enumerate(f1):
        if v > max(f1) * 0.5: bars[i].set_color(ORANGE)
        ax.text(i, v + max(f1) * 0.04, f"{v:.3f}", ha="center", fontsize=9.5, color=INK)
    mu, sd = float(np.mean(f1)), float(np.std(f1))
    ax.axhline(mu, color=BLUE, lw=1.4, ls="--", zorder=4)
    ax.text(len(f1) - 0.4, mu + max(f1) * 0.05, f"mean={mu:.3f} ± {sd:.3f}",
            fontsize=9.5, color=BLUE, ha="right")
    # 對照：規則的 F1
    ax.axhline(D["sourcenode"]["f1"], color=GREEN, lw=1.6, zorder=4)
    ax.text(0.05, D["sourcenode"]["f1"] - max(f1) * 0.12,
            f"SourceNode 規則 F1={D['sourcenode']['f1']:.3f}（零訓練、無隨機性）",
            fontsize=9.5, color=GREEN)
    ax.set_ylim(0, max(max(f1), D["sourcenode"]["f1"]) * 1.2)
    style(ax, xlabel="random seed", ylabel="F1", grid_axis="y",
          title="DeepLog 的 F1 完全由隨機初始化決定",
          sub=f"5 個 seed 的 F1 從 {min(f1):.3f} 到 {max(f1):.3f}；std({sd:.3f}) 比 mean({mu:.3f}) 還大 → 單次執行的數字沒有意義")
    save(fig, "v2_fig3_seeds.png")


# =============================================================================
# 圖 V4：互補性 —— 誰抓到了什麼
# =============================================================================
def fig_complement():
    fig, ax = plt.subplots(figsize=(9.5, 3.6))
    # 直接用 eval_v2.py 算好的逐行交集計數（不由 recall 反推）
    O = S["overlap"]
    total = O["total"]

    def types(key):
        d = O.get(key + "_types", {})
        return " / ".join(f"{k} {v}" for k, v in sorted(d.items(), key=lambda x: -x[1]))

    segs = [(f"只有統計規則抓到\n({types('l1_only')})",  O["l1_only"], BLUE),
            (f"兩者都抓到\n({types('both')})",           O["both"],    GREY),
            (f"只有 SourceNode 抓到\n({types('sn_only')})", O["sn_only"], GREEN),
            (f"都漏掉\n({types('missed')})",             O["missed"],  RED)]
    left = 0
    for lbl, v, c in segs:
        if v <= 0: continue
        ax.barh([0], [v], left=left, color=c, zorder=3, height=0.5)
        ax.text(left + v / 2, 0, f"{int(round(v))}", ha="center", va="center",
                fontsize=11, color="white", fontweight="bold")
        ax.text(left + v / 2, -0.42, lbl, ha="center", va="top", fontsize=9, color=SUB)
        left += v
    ax.set_xlim(0, total); ax.set_ylim(-1.1, 0.5)
    ax.set_yticks([])
    style(ax, xlabel=f"異常筆數（共 {total}）", grid_axis="x",
          title="兩條零訓練規則的互補性",
          sub="沒有任何一條規則單獨足夠：R 只有 SourceNode 看得到，T 只有統計規則看得到")
    save(fig, "v2_fig4_complement.png")


# =============================================================================
# 圖 V5：新舊資料對照 —— R recall
# =============================================================================
def fig_old_vs_new():
    fig, ax = plt.subplots(figsize=(9.5, 4))
    labels = ["IsolationForest", "RandomForest", "DeepLog", "SourceNode 規則\n（本次新增）"]
    old = [0, 0, 0, None]                       # 舊實驗消融後的真實 R recall
    new = [None, None, D["deeplog"].get("R", 0) or 0, D["sourcenode"].get("R", 0) or 0]
    x = np.arange(len(labels))
    ax.bar(x[:3] - 0.0, [0, 0, 0], width=0.5, color=GREY, zorder=3, label="舊實驗（消融後真實值）")
    for i in range(3):
        ax.text(i, 0.02, "0%", ha="center", fontsize=10, color=RED, fontweight="bold")
    ax.bar([3], [new[3]], width=0.5, color=GREEN, zorder=3, label="新格式 SourceNode 規則")
    ax.text(3, new[3] + 0.03, f"{new[3]:.0%}", ha="center", fontsize=12,
            color=GREEN, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9.5)
    ax.set_ylim(0, 1.18)
    ax.set_yticks([0, .25, .5, .75, 1]); ax.set_yticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax.legend(loc="upper left", frameon=False, fontsize=9.5)
    style(ax, ylabel="R (否認攻擊) recall", grid_axis="y",
          title="R 否認攻擊：三個 ML 模型全部 0%，一條規則 100%",
          sub="不是模型變好了，是 log 補上了來源身分欄位 —— 破綻從「不存在於資料中」變成「一眼可見」")
    save(fig, "v2_fig5_old_vs_new.png")


# =============================================================================
# 圖 V6：攻擊比例 vs 檢測準度（來自 eval_ratio.py）
# =============================================================================
def fig_ratio():
    path = os.path.join(OUT, "ratio_summary.json")
    if not os.path.exists(path):
        print("  ⚠ 找不到 ratio_summary.json，跳過（請先跑 eval_ratio.py）")
        return
    R = json.load(open(path, encoding="utf-8"))["results"]
    order = ["第1層 統計規則", "SourceNode==null", "sensor_no_echo", "統計 OR SourceNode"]
    colors = {"第1層 統計規則": BLUE, "SourceNode==null": GREEN,
              "sensor_no_echo": ORANGE, "統計 OR SourceNode": INK}

    fig, axes = plt.subplots(1, 2, figsize=(13, 4.6))
    for ax, key, ttl, note in [
        (axes[0], "f1",     "F1 隨比例劇烈變化",
         "同一個偵測器、同一批攻擊 —— 只因正常流量多寡，F1 就從 0.10 變到 0.75"),
        (axes[1], "recall", "Recall 完全不受比例影響",
         "recall 是「異常母體內的比率」，稀釋正常流量不影響它"),
    ]:
        for name in order:
            pts = sorted(R[name].values(), key=lambda v: v["actual"])
            xs = [v["actual"] * 100 for v in pts]
            ys = [v[key]["mean"] for v in pts]
            ax.plot(xs, ys, "o-", color=colors[name], lw=1.8, ms=4.5,
                    label=name, zorder=3)
        ax.set_xscale("log")
        ax.set_ylim(0, 1.05)
        ax.set_xticks([0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10])
        ax.set_xticklabels(["0.05%", "0.1%", "0.2%", "0.5%", "1%", "2%", "5%", "10%"],
                           fontsize=8.5)
        style(ax, xlabel="異常比例（log 尺度）", ylabel=key.upper(),
              grid_axis="y", title=ttl, sub=note)
    axes[0].legend(loc="upper left", frameon=False, fontsize=8.5)
    fig.tight_layout(rect=[0, 0, 1, 0.92])
    fig.text(0.005, 0.99, "攻擊比例 vs 檢測準度 —— F1 會騙人，recall 不會",
             fontsize=14, color=INK, ha="left", va="top")
    fig.text(0.005, 0.945,
             "固定同一批 48 筆異常，只改變摻入的正常行數量；每點重複抽樣 20 次",
             fontsize=9.5, color=SUB, ha="left", va="top")
    save(fig, "v2_fig6_ratio.png")


if __name__ == "__main__":
    print("產生圖表 →", FIG)
    fig_detectors()
    fig_per_attack()
    fig_seeds()
    fig_complement()
    fig_old_vs_new()
    fig_ratio()
    print("完成")
