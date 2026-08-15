#!/usr/bin/env python3
# =============================================================================
# audit_graph.py ── 建圖後的防洩漏／資料健康稽核（第三輪 P6）
# =============================================================================
# 為什麼需要這個檔：
#   本專案已經踩過**五次**「先報了高分，才發現原因」的洩漏：
#     1. 攻擊專屬模板（正常出現 0 次）→ 序列模型記住模板就滿分
#     2. dist_ts_occurrence=0 的 parser 產物 → 數值模型記住「Motor 行沒有距離值」
#     3. 邊標籤把整秒的正常通道都標成攻擊 → 模型只要偵測攻擊秒就 recall 1.0
#     4. 整數秒對齊造成的計時假象 → honest motor 的訂閱抖動被算成 40cm 假偏差
#     5. ground truth 記號 " #MAL" 讓 log 行長 5 bytes → 直接反映在 pcap 位元組數
#   每一次都是事後才抓到。這支腳本把「事後回頭查」變成「建圖後就自動查」。
#
# 用法： ml/venv/bin/python net/audit_graph.py <capture_dir> [更多 capture_dir ...]
#   只讀 graph/ 底下的 CSV，不重建圖、不需要 torch，秒級完成。
#
# 四項檢查（每項都會印 PASS / WARN，並說明 WARN 代表什麼方法會受影響）：
#   A. ground truth 記號是否改變可觀測量（逐節點 bytes_c2s：正常秒 vs 惡意秒）
#   B. 同群 motor 在正常秒的值一致性（peer 一致性方法的成立前提）
#   C. 每個節點是否有 2-hop peer（peer 重建的合法對象）
#   D. 跨節點值特徵的逐場景分布（report_dev_max / report_dev_own_max）
# =============================================================================
import os, sys, itertools
import pandas as pd
import numpy as np

WARN = []
def out(s=""):
    print(s)
def warn(section, msg):
    WARN.append((section, msg))


def load(gdir):
    n = pd.read_csv(os.path.join(gdir, "nodes.csv"))
    e = pd.read_csv(os.path.join(gdir, "edges.csv"))
    g = pd.read_csv(os.path.join(gdir, "graphs.csv"))
    n = n.merge(g[["scenario", "sec", "label"]], on=["scenario", "sec"],
                suffixes=("_node", ""))
    return n, e, g


def groups_of(e, scen):
    """從訂閱邊推出「誰跟誰同群」。這是拓撲資訊，pcap 直接可觀察。"""
    sub = e[(e.scenario == scen) &
            e.dst.str.startswith("sensor_server") &
            e.src.str.startswith("motor_")]
    if sub.empty:
        return {}
    # 一台 motor 可能在少數秒有雜訊邊 → 取眾數當它的歸屬
    owner = sub.groupby("src").dst.agg(lambda x: x.mode().iloc[0])
    grp = {}
    for m, s in owner.items():
        grp.setdefault(s, []).append(m)
    return grp


# ---------------------------------------------------------------------------
# A. ground truth 記號是否改變可觀測量
# ---------------------------------------------------------------------------
MARKER_MAX = 20     # 記號等級的位移上限（" #MAL" 是 5 bytes）
MARKER_MIN = 3      # 以下視為小樣本噪音（實測誠實節點會出現 ±1）
QSPREAD_MAX = 1     # 真正的常數位移散布為 0；放寬到 2 會誤報（實測 [2,2,0]）

def check_marker(n):
    """判準（用已知案例校準過，見下方數字）：

    ground truth 記號是**每一行都加固定長度**，所以它在 bytes_c2s 上表現為
    「q25/q50/q75 三個分位位移完全一致，且幅度是記號等級（幾 bytes）」。
    真實的攻擊流量差異也可能三分位一致，但幅度是**幾百 bytes**。用兩者一起判。

      舊資料集 compromised/log_writer_4（已知洩漏）  位移 = [5, 5, 5]   ← 記號
      舊資料集 compromised/log_writer_1（誠實）      位移 = [0, 0, 0]
      現用資料集 compromised/log_writer_9（攻擊者）  位移 = [0, 0, 0]   ← 修好了
      現用資料集 T/log_writer_1（真實攻擊流量）      位移 = [344, 345, 344] ← 非記號
    """
    out("\n[A] ground truth 記號的可觀測性")
    out(f"    判準：三分位位移一致（相差 ≤{QSPREAD_MAX}）且幅度在 "
        f"{MARKER_MIN}~{MARKER_MAX} bytes → 疑似記號洩漏。")
    out("    幅度上百的一致位移是真實攻擊流量，不是洩漏，另外列出不算警告。")
    bad, info = 0, []
    for sc in sorted(n.scenario.unique()):
        s = n[n.scenario == sc]
        if s.label.sum() == 0:
            continue
        for nd in sorted(s.node.unique()):
            q = s[s.node == nd]
            a, b = q[q.label == 0].bytes_c2s, q[q.label == 1].bytes_c2s
            if len(a) < 5 or len(b) < 3:
                continue
            sh = np.array([b.quantile(x) - a.quantile(x) for x in (.25, .5, .75)])
            mag, spread = abs(sh[1]), sh.max() - sh.min()
            if spread > QSPREAD_MAX or mag < MARKER_MIN:
                continue
            if mag <= MARKER_MAX:
                out(f"    ⚠ {sc}/{nd}: 三分位位移 {sh.astype(int).tolist()} "
                    f"—— 記號等級的常數位移")
                bad += 1
            else:
                info.append(f"{sc}/{nd} ({sh[1]:+.0f})")
    if info:
        out(f"    （真實攻擊流量差異，非洩漏）{', '.join(info[:8])}"
            f"{' …' if len(info) > 8 else ''}")
    if bad:
        warn("A", f"{bad} 個節點有記號等級的常數位移 → **監督式**結果不可用"
                  "（one-class 只用 benign 訓練，不受影響）")
    else:
        out("    PASS：沒有節點出現記號等級的常數位移。")


# ---------------------------------------------------------------------------
# B. 同群 motor 在正常秒的值一致性
# ---------------------------------------------------------------------------
def check_group_sync(n, e):
    out("\n[B] 同群 motor 在【正常秒】的值一致性")
    out("    判準：同群應逐位元相同（中位差 0.000）。非 0 代表兩台抓到同一台 sensor 的")
    out("    **不同但都合法**的樣本（訂閱取樣相位漂移）—— 不是資料損壞，但會讓")
    out("    peer 一致性方法（GNN peer 重建、motor 互比）在該場景失去可比性。")
    bad = 0
    for sc in sorted(n.scenario.unique()):
        grp = groups_of(e, sc)
        b = n[(n.scenario == sc) & (n.report_val != 0) & (n.label == 0)]
        if b.empty or not grp:
            continue
        piv = b.pivot_table(index="sec", columns="node", values="report_val")
        cells = []
        for sensor, mem in sorted(grp.items()):
            mem = [m for m in mem if m in piv.columns]
            if len(mem) < 2:
                continue
            worst = 0.0
            for x, y in itertools.combinations(mem, 2):
                dd = piv[[x, y]].dropna()
                if len(dd):
                    worst = max(worst, float((dd[x] - dd[y]).abs().median()))
            tag = " ⚠" if worst > 0.1 else ""
            if worst > 0.1:
                bad += 1
            cells.append(f"{sensor.replace('sensor_server','s')}:"
                         f"{'+'.join(m.replace('motor_','m') for m in mem)}={worst:.3f}{tag}")
        out(f"    {sc:<20} " + "   ".join(cells))
    if bad:
        warn("B", f"{bad} 個（場景×群）同群失步 → 該格對 **peer 一致性方法** 不可用；"
                  "對 report_dev_own（比自己的 sensor）與 log 規則無影響")
    else:
        out("    PASS：所有場景所有群都保持同步。")


# ---------------------------------------------------------------------------
# C. 每個節點是否有 2-hop peer
# ---------------------------------------------------------------------------
def check_has_peer(n, e):
    out("\n[C] 哪些節點有 2-hop peer（＝可以當 peer 重建的對象）")
    out("    判準：沒有 peer 的節點若被當成重建目標，等於要模型在零資訊下猜一個")
    out("    連續值 → 殘差大且隨機，會霸佔 max-pooling 的圖分數。")
    rows = {}
    for sc in sorted(n.scenario.unique()):
        grp = groups_of(e, sc)
        has = {m for mem in grp.values() if len(mem) >= 2 for m in mem}
        s = n[(n.scenario == sc) & (n.report_val != 0)]
        for nt in sorted(s.node_type.unique()):
            q = s[s.node_type == nt]
            rows.setdefault(nt, []).append(q.node.isin(has).mean())
    for nt, v in rows.items():
        flag = "" if np.mean(v) > 0.9 else "   ← 不可當重建目標"
        out(f"    {nt:<14} 有值節點中「有 peer」的比例 {np.mean(v):>6.1%}{flag}")
    if any(np.mean(v) < 0.9 for v in rows.values()):
        warn("C", "有型別的節點沒有 peer → 重建 loss 與圖分數必須把它們排除"
                  "（graph_clf.py 的 score_mask 已處理）")


# ---------------------------------------------------------------------------
# D. 跨節點值特徵的逐場景分布
# ---------------------------------------------------------------------------
def check_value_feats(n):
    out("\n[D] 跨節點值特徵的逐場景分布（正常秒應為 0，只有值竄改場景的惡意秒非 0）")
    for col in ["report_dev_max", "report_dev_own"]:
        if col not in n.columns:
            continue
        out(f"    {col}:")
        for sc in sorted(n.scenario.unique()):
            s = n[n.scenario == sc]
            a = s[s.label == 0][col].max()
            b = s[s.label == 1][col].max() if s.label.sum() else float("nan")
            flag = "  ⚠ 正常秒非 0" if a > 0.1 else ""
            out(f"      {sc:<20} 正常秒 max={a:>8.3f}   惡意秒 max={b:>8.3f}{flag}")
            if a > 0.1:
                warn("D", f"{sc}/{col} 正常秒非 0 → 可能是計時假象，先別信這個場景的分數")


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: audit_graph.py <capture_dir> [更多 capture_dir ...]")
    for root in sys.argv[1:]:
        gdir = os.path.join(os.path.abspath(root), "graph")
        if not os.path.isdir(gdir):
            out(f"跳過（沒有 graph/）: {root}")
            continue
        out("=" * 78)
        out(f"建圖稽核: {root}")
        out("=" * 78)
        n, e, g = load(gdir)
        out(f"圖 {len(g)}  攻擊圖 {int(g.label.sum())} ({g.label.mean():.2%})  "
            f"場景 {sorted(g.scenario.unique())}")
        WARN.clear()
        check_marker(n)
        check_group_sync(n, e)
        check_has_peer(n, e)
        check_value_feats(n)
        out("\n" + "-" * 78)
        if WARN:
            out(f"稽核結果：{len(WARN)} 項需要注意")
            for sec, m in WARN:
                out(f"  [{sec}] {m}")
        else:
            out("稽核結果：全部通過")
        out("")


if __name__ == "__main__":
    main()
