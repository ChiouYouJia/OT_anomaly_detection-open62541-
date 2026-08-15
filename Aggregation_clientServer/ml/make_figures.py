#!/usr/bin/env python3
# =============================================================================
# make_figures.py ── 把 EXPERIMENTS.md 的表格畫成圖表
# =============================================================================
# 產生 ml/figures/*.png，並由 EXPERIMENTS.md 以 ![](figures/xxx.png) 引用。
#
# 數據來源：全部來自 ml/out/ 的實驗輸出（ablation_leakage.txt / sweep_deeplog.txt
#   / hybrid_results.txt）。此處以常數寫死，與那三份報告的數字一一對應，
#   修改實驗後請同步更新（或改為解析 txt）。
#
# 設計原則（避免常見的圖表錯誤）：
#   - 不用雙 y 軸；不同量綱的指標分開畫或各自成組
#   - 類別色固定順序、不循環；色盲安全（藍/橘/綠三色已驗證 CVD ΔE >= 9）
#   - 直接標數值，不依賴讀者估算長度
#   - 淺色背景、細網格線、無邊框，列印友善
#
# 執行： ml/venv/bin/python ml/make_figures.py
# =============================================================================
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
FIG  = os.path.join(HERE, "figures")
os.makedirs(FIG, exist_ok=True)

# ---- 中文字型 ----
# 字型檔 12MB，不進版控（見 .gitignore），首次執行時自動下載到 ml/assets/。
FONT_URL  = ("https://github.com/notofonts/noto-cjk/raw/main/"
             "Sans/Variable/TTF/Subset/NotoSansTC-VF.ttf")
FONT_PATH = os.path.join(HERE, "assets", "NotoSansTC.ttf")

if not os.path.exists(FONT_PATH):
    os.makedirs(os.path.dirname(FONT_PATH), exist_ok=True)
    print(f"首次執行：下載中文字型 → {FONT_PATH}")
    try:
        import urllib.request
        urllib.request.urlretrieve(FONT_URL, FONT_PATH)
        print("  ✓ 字型下載完成")
    except Exception as e:
        print(f"  ⚠ 字型下載失敗（{e}），中文將顯示為方框")

if os.path.exists(FONT_PATH):
    fm.fontManager.addfont(FONT_PATH)
    plt.rcParams["font.family"] = fm.FontProperties(fname=FONT_PATH).get_name()
    # 可變字重字型(VF)：matplotlib 無法解析具名字重實例，會發出 findfont 警告並
    # 退回 weight 100。字重統一交給字型本身，這裡只把噪音警告關掉。
    # （強調改用顏色而非粗體，見各圖的 color=RED 用法）
    import logging
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
else:
    print("⚠ 找不到 ml/assets/NotoSansTC.ttf，中文可能顯示為方框")
plt.rcParams["axes.unicode_minus"] = False

# ---- 配色（已通過色盲安全驗證的三色）----
BLUE, ORANGE, GREEN = "#2a78d6", "#eb6834", "#1baf7a"
RED, GREY = "#d03b3b", "#898781"
INK, SUB  = "#0b0b0b", "#52514e"
GRID      = "#e1e0d9"

DPI = 160


def style(ax, xlabel=None, ylabel=None, title=None, sub=None, grid_axis="x"):
    """統一的細網格 / 無邊框樣式。"""
    for s in ("top", "right", "left" if grid_axis == "x" else "bottom"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom" if grid_axis == "x" else "left"].set_color("#c3c2b7")
    ax.grid(axis=grid_axis, color=GRID, lw=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(colors=SUB, labelsize=9.5, length=0)
    if xlabel: ax.set_xlabel(xlabel, fontsize=10, color=SUB)
    if ylabel: ax.set_ylabel(ylabel, fontsize=10, color=SUB)
    if title:
        ax.set_title(title, fontsize=13, color=INK,
                     loc="left", pad=18 if sub else 10)
    if sub:
        ax.text(0, 1.02, sub, transform=ax.transAxes, fontsize=9.5,
                color=SUB, va="bottom")


def save(fig, name):
    path = os.path.join(FIG, name)
    fig.savefig(path, dpi=DPI, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ figures/{name}")


# =============================================================================
# 圖 1：R 消融 — 洩漏前後的 per-attack recall
# =============================================================================
def fig_ablation():
    models = ["IsolationForest", "RandomForest", "DeepLog"]
    attacks = ["S", "T", "R", "RP"]
    before = {"IsolationForest": [22, 100, 100, 0],
              "RandomForest":    [100, 80, 100, 100],
              "DeepLog":         [96, 90, 100, 50]}
    after  = {"IsolationForest": [0, 100, 0, 0],
              "RandomForest":    [100, 80, 0, 100],
              "DeepLog":         [74, 100, 0, 50]}

    fig, axes = plt.subplots(1, 3, figsize=(12.4, 4.0), sharey=True)
    y = np.arange(len(attacks)); h = 0.36

    for ax, m in zip(axes, models):
        ax.barh(y + h/2, before[m], h, label="洩漏未關閉", color=BLUE, zorder=3)
        ax.barh(y - h/2, after[m],  h, label="洩漏關閉後", color=ORANGE, zorder=3)
        for i, (b, a) in enumerate(zip(before[m], after[m])):
            ax.text(b + 2, i + h/2, f"{b}%", va="center", fontsize=9, color=INK)
            ax.text(a + 2, i - h/2, f"{a}%", va="center", fontsize=9, color=INK)
        # 只在 R 這一列標「崩潰」，位置固定在右側留白處
        ri = attacks.index("R")
        ax.text(126, ri, "← 崩潰", va="center", ha="right", fontsize=9.5,
                color=RED)
        ax.set_yticks(y); ax.set_yticklabels(attacks)
        ax.set_xlim(0, 130); ax.set_xticks([0, 50, 100])
        ax.set_xticklabels(["0", "50%", "100%"])
        style(ax, title=m)
        ax.invert_yaxis()

    axes[0].set_ylabel("攻擊類別", fontsize=10, color=SUB)
    axes[0].legend(loc="lower right", frameon=False, fontsize=9.5)
    fig.suptitle("圖 1  R 消融實驗：關閉洩漏管道後 R 全面崩潰至 0%",
                 fontsize=14, color=INK, x=0.005, ha="left", y=1.13)
    fig.text(0.005, 1.045, "S 是對照組：同樣受影響卻沒有崩潰，因為它另有真實可分特徵",
             fontsize=10, color=SUB, ha="left")
    save(fig, "fig1_ablation.png")


# =============================================================================
# 圖 2：混合偵測器 — F1 / Recall / FPR
# =============================================================================
def fig_hybrid():
    names = ["第1層\n統計規則", "第2層\nDeepLog", "混合 OR", "混合 AND"]
    f1   = [0.456, 0.273, 0.301, 0.462]
    rec  = [0.837, 0.694, 0.918, 0.612]
    fpr  = [3.92, 7.23, 8.93, 2.22]

    fig, axes = plt.subplots(1, 3, figsize=(12.4, 4.2))
    x = np.arange(len(names))

    for ax, vals, ttl, color, fmt, hi_best in [
        (axes[0], f1,  "F1（越高越好）",      BLUE,   "{:.3f}", max),
        (axes[1], rec, "Recall（越高越好）",   ORANGE, "{:.3f}", max),
        (axes[2], fpr, "FPR 誤報率（越低越好）", GREEN,  "{:.2f}%", min),
    ]:
        best = hi_best(vals)
        colors = [color if v != best else RED for v in vals]
        bars = ax.bar(x, vals, 0.62, color=colors, zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width()/2, v, fmt.format(v),
                    ha="center", va="bottom", fontsize=9.5,
                    color=RED if v == best else INK)
        ax.set_xticks(x); ax.set_xticklabels(names, fontsize=9)
        ax.set_ylim(0, max(vals) * 1.22)
        style(ax, title=ttl, grid_axis="y")

    fig.tight_layout(rect=[0, 0, 1, 0.88])
    fig.suptitle("圖 2  混合偵測器對照：OR 疊加 recall 最高，但 F1 反而低於第1層",
                 fontsize=14, color=INK, x=0.005, ha="left", y=0.99)
    fig.text(0.005, 0.915,
             "紅色為該指標最佳者　·　全部攻擊場景 2,345 行 / 49 異常　·　誤報會相加：3.92% + 7.23% → 8.93%",
             fontsize=10, color=SUB, ha="left")
    save(fig, "fig2_hybrid.png")


# =============================================================================
# 圖 3：互補性分析
# =============================================================================
def fig_overlap():
    labels = ["只有第1層抓到", "只有第2層抓到", "兩層都抓到", "兩層都漏掉"]
    vals   = [11, 4, 30, 4]
    colors = [BLUE, ORANGE, GREY, RED]
    notes  = ["序列模型看不到的\n參數重複（RP）", "統計規則沒涵蓋的\n序列轉移異常",
              "", "主要是 R"]

    fig, ax = plt.subplots(figsize=(10.2, 3.0))
    left = 0
    for v, c, l in zip(vals, colors, labels):
        ax.barh([0], [v], left=left, color=c, height=0.5, zorder=3)
        ax.text(left + v/2, 0, str(v), ha="center", va="center",
                fontsize=13, color="white")
        left += v

    left = 0
    for v, l, n in zip(vals, labels, notes):
        ax.text(left + v/2, 0.42, l, ha="center", fontsize=9.5, color=INK)
        if n:
            ax.text(left + v/2, -0.42, n, ha="center", va="top",
                    fontsize=8.5, color=SUB, linespacing=1.4)
        left += v

    ax.set_xlim(0, 49); ax.set_ylim(-0.95, 0.75)
    ax.set_yticks([]); ax.set_xticks([])
    for s in ax.spines.values(): s.set_visible(False)
    ax.set_title("圖 3  互補性分析：兩層獨有的抓捕不重疊（11 vs 4）",
                 fontsize=14, color=INK, loc="left", pad=34)
    ax.text(0, 1.10, "全部攻擊場景 · 49 筆真異常 · 這是「需要疊加」的實質證據",
            transform=ax.transAxes, fontsize=10, color=SUB, va="bottom")
    save(fig, "fig3_overlap.png")


# =============================================================================
# 圖 4：超參網格 PR-AUC
# =============================================================================
def fig_grid():
    windows = [5, 10, 20]; hiddens = [32, 64]
    pr = {(5,32):0.087,(5,64):0.100,(10,32):0.098,
          (10,64):0.100,(20,32):0.110,(20,64):0.114}

    fig, ax = plt.subplots(figsize=(8.2, 4.0))
    x = np.arange(len(windows)); w = 0.36
    for i, h in enumerate(hiddens):
        vals = [pr[(win, h)] for win in windows]
        off = (i - 0.5) * w
        bars = ax.bar(x + off, vals, w, label=f"hidden={h}",
                      color=[BLUE, ORANGE][i], zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x()+b.get_width()/2, v, f"{v:.3f}",
                    ha="center", va="bottom", fontsize=9, color=INK)

    ax.axhline(0.114, color=RED, lw=1.2, ls="--", zorder=4)
    ax.text(-0.42, 0.1175, "最佳 0.114", fontsize=9, color=RED, ha="left")
    ax.set_xticks(x); ax.set_xticklabels([f"window={w_}" for w_ in windows])
    ax.set_ylim(0, 0.152)
    ax.legend(frameon=False, fontsize=9.5, loc="upper left")
    style(ax, ylabel="PR-AUC", grid_axis="y",
          title="圖 4  超參網格：整個網格的 PR-AUC 都很低（0.087 ~ 0.114）",
          sub="最佳設定只比先前預設(window=10,hidden=64) 高 0.014 → 調參救不了它")
    save(fig, "fig4_grid.png")


# =============================================================================
# 圖 5：top-k 取捨 + PR 天花板
# =============================================================================
def fig_topk():
    ks   = [1, 2, 3, 5, 8]
    prec = [0.169, 0.188, 0.190, 0.074, 0.078]
    rec  = [0.755, 0.755, 0.714, 0.204, 0.204]
    f1   = [0.276, 0.301, 0.300, 0.108, 0.113]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.4, 4.2))

    x = np.arange(len(ks))
    ax1.plot(x, prec, "o-", color=BLUE,   lw=2, ms=7, label="Precision", zorder=3)
    ax1.plot(x, rec,  "s-", color=ORANGE, lw=2, ms=7, label="Recall", zorder=3)
    ax1.plot(x, f1,   "^-", color=GREEN,  lw=2, ms=7, label="F1", zorder=3)
    ax1.axvspan(2.5, 4.4, color=RED, alpha=0.07, zorder=1)
    ax1.text(3.45, 0.70, "k≥5 斷崖\nS/RP 歸零", ha="center", fontsize=9.5,
             color=RED, linespacing=1.5)
    ax1.set_xticks(x); ax1.set_xticklabels([f"k={k}" for k in ks])
    ax1.set_xlim(-0.4, 4.4); ax1.set_ylim(0, 0.88)
    ax1.legend(frameon=False, fontsize=9.5)
    style(ax1, grid_axis="y", title="top-k 取捨：k 不是超參，是工作點")

    # PR 天花板
    r = [0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0]
    p = [0.190]*7 + [0.022]*3
    ax2.step(r, p, where="post", color=BLUE, lw=2.4, zorder=3)
    ax2.fill_between(r, p, step="post", color=BLUE, alpha=0.12, zorder=2)
    ax2.annotate("斷崖：precision 0.19 → 0.02",
                 xy=(0.8, 0.022), xytext=(0.44, 0.115),
                 fontsize=9.5, color=RED,
                 arrowprops=dict(arrowstyle="->", color=RED, lw=1.4))
    ax2.set_xlim(0.08, 1.02); ax2.set_ylim(0, 0.225)
    style(ax2, xlabel="Recall", ylabel="可達的最佳 Precision", grid_axis="y",
          title="PR 天花板：recall 0.7→0.8 之間崩塌")

    fig.tight_layout(rect=[0, 0, 1, 0.91])
    fig.suptitle("圖 5  top-k 取捨與 PR 曲線天花板（window=20, hidden=64）",
                 fontsize=14, color=INK, x=0.005, ha="left", y=0.985)
    save(fig, "fig5_topk.png")


# =============================================================================
# 圖 6：多 seed 誤差範圍
# =============================================================================
def fig_seeds():
    rows = [("T recall",  1.000, 0.000, 1.000, 1.000),
            ("S recall",  0.615, 0.097, 0.519, 0.741),
            ("RP recall", 0.550, 0.112, 0.500, 0.750),
            ("R recall",  0.150, 0.137, 0.000, 0.250),
            ("F1",        0.272, 0.024, 0.239, 0.300),
            ("PR-AUC",    0.121, 0.014, 0.106, 0.142)]

    fig, ax = plt.subplots(figsize=(9.6, 4.4))
    y = np.arange(len(rows))[::-1]
    for yi, (name, mean, std, lo, hi) in zip(y, rows):
        c = GREEN if std == 0 else (RED if name == "R recall" else BLUE)
        ax.barh(yi, mean, 0.5, color=c, alpha=0.85, zorder=3)
        ax.plot([lo, hi], [yi, yi], color=INK, lw=1.8, zorder=4)
        for e in (lo, hi):
            ax.plot([e, e], [yi-0.13, yi+0.13], color=INK, lw=1.8, zorder=4)
        ax.text(max(hi, mean) + 0.02, yi, f"{mean:.3f} ± {std:.3f}",
                va="center", fontsize=9.5, color=INK)

    ax.text(1.19, y[0], "← 唯一 std=0", va="center", fontsize=9, color=GREEN)
    ax.set_yticks(y); ax.set_yticklabels([r[0] for r in rows])
    ax.set_xlim(0, 1.42); ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    style(ax, xlabel="數值（誤差線 = min–max 範圍）",
          title="圖 6  5 個 random seed 的誤差範圍",
          sub="F1 的 std=0.024 → 先前「語意版 0.54 vs 整數版 0.46」的差距落在雜訊內")
    save(fig, "fig6_seeds.png")


# =============================================================================
# 圖 7：Four_combined 場景
# =============================================================================
def fig_fourcombined():
    names = ["第1層\n統計規則", "第2層\nDeepLog", "混合 OR", "混合 AND"]
    prec  = [0.500, 0.312, 0.267, 1.000]
    rec   = [0.733, 0.667, 0.800, 0.600]
    f1    = [0.595, 0.426, 0.400, 0.750]
    fpr   = [1.62, 3.24, 4.86, 0.00]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.4, 4.2),
                                   gridspec_kw={"width_ratios": [1.7, 1]})
    x = np.arange(len(names)); w = 0.26
    for i, (vals, lab, c) in enumerate([(prec,"Precision",BLUE),
                                        (rec,"Recall",ORANGE),
                                        (f1,"F1",GREEN)]):
        off = (i - 1) * w
        bars = ax1.bar(x + off, vals, w, label=lab, color=c, zorder=3)
        for b, v in zip(bars, vals):
            ax1.text(b.get_x()+b.get_width()/2, v, f"{v:.2f}",
                     ha="center", va="bottom", fontsize=8, color=INK)
    ax1.set_xticks(x); ax1.set_xticklabels(names, fontsize=9)
    ax1.set_ylim(0, 1.18)
    ax1.legend(frameon=False, fontsize=9.5, ncol=3, loc="upper left")
    style(ax1, grid_axis="y", title="Precision / Recall / F1")

    colors = [GREEN if v > 0 else RED for v in fpr]
    bars = ax2.bar(x, fpr, 0.6, color=colors, zorder=3)
    for b, v in zip(bars, fpr):
        ax2.text(b.get_x()+b.get_width()/2, v + 0.08, f"{v:.2f}%",
                 ha="center", fontsize=9.5,
                 color=RED if v == 0 else INK)
    ax2.text(3, 0.42, "零誤報", ha="center", fontsize=9.5, color=RED)
    ax2.set_xticks(x); ax2.set_xticklabels(names, fontsize=9)
    ax2.set_ylim(0, 5.6)
    style(ax2, ylabel="FPR (%)", grid_axis="y", title="誤報率")

    fig.tight_layout(rect=[0, 0, 1, 0.88])
    fig.suptitle("圖 7  四攻擊混合場景 Four_combined：AND 疊加達 precision 1.000 / FPR 0%",
                 fontsize=14, color=INK, x=0.005, ha="left", y=0.99)
    fig.text(0.005, 0.915, "694 行 / 15 異常 · 唯一同時含 S+T+R+RP 的最真實場景",
             fontsize=10, color=SUB, ha="left")
    save(fig, "fig7_four_combined.png")


if __name__ == "__main__":
    print("產生圖表 → ml/figures/")
    fig_ablation()
    fig_hybrid()
    fig_overlap()
    fig_grid()
    fig_topk()
    fig_seeds()
    fig_fourcombined()
    print("\n完成。在 EXPERIMENTS.md 中以 ![](figures/xxx.png) 引用。")
