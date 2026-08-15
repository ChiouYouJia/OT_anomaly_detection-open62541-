#!/usr/bin/env python3
# =============================================================================
# backfill_win_feats.py ── 把 sensor 的「窗內樣本」欄位補進**既有**資料集
# =============================================================================
# 為什麼需要這支：build_graph.py 已經會產出 win_val_prev / win_val_cur /
# win_val_next（見該檔 1:1 pair 拓撲的說明），但既有資料集（例如 3s6m）是舊版
# 建的，沒有這三欄。要在**已知答案的舊資料**上先驗證 HOP=1 的機制是否成立
# （TOPO_PAIR3_GNN_DESIGN.md 的 1-4 節），又不想為此重跑一次 pcap 解析
# （scapy 逐封包，很慢）—— 這三欄**只來自 anomaly.log**，與 pcap 無關，
# 所以可以單獨補算。
#
# 安全性：原 nodes.csv 會先備份成 nodes.csv.bak（已存在則不覆蓋備份）。
# 若欄位已存在則直接覆寫該三欄，其餘欄位一律不動。
#
# 用法： ml/venv/bin/python net/backfill_win_feats.py <capture_dir>
# =============================================================================
import os, shutil, sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_graph as bg

WIN_COLS = ["win_val_prev", "win_val_cur", "win_val_next"]


def main():
    root = os.path.abspath(sys.argv[1])
    gdir = os.path.join(root, "graph")
    npath = os.path.join(gdir, "nodes.csv")
    if not os.path.exists(npath):
        sys.exit(f"找不到 {npath}")

    nodes = pd.read_csv(npath)
    # (scenario, sec, sensor 節點名) → 三個窗內值
    vals = {}
    for scen in sorted(os.listdir(root)):
        d = os.path.join(root, scen)
        alog = os.path.join(d, "anomaly.log")
        if not os.path.isdir(d) or scen == "graph" or not os.path.exists(alog):
            continue
        res = bg.read_log(alog)
        sts = res[-1]["sensor_truth_src"]
        secs = set(sts)
        for t in secs:
            cur = bg._sensor_node_vals(sts, t)
            prev = bg._sensor_node_vals(sts, t - 1)
            nxt = bg._sensor_node_vals(sts, t + 1)
            for nm, v in cur.items():
                # 缺樣本時退回當秒值，與 build_graph 的行為一致
                vals[(scen, t, nm)] = (prev.get(nm, v), v, nxt.get(nm, v))
        print(f"  ✓ {scen:20} 秒數={len(secs):6} sensor 節點={len(set(k[2] for k in vals if k[0]==scen))}")

    is_sensor = nodes.node.astype(str).str.startswith("sensor_server")
    key = list(zip(nodes.scenario, nodes.sec, nodes.node))
    for i, col in enumerate(WIN_COLS):
        nodes[col] = [vals.get(k, (0.0, 0.0, 0.0))[i] if s else 0.0
                      for k, s in zip(key, is_sensor)]

    bak = npath + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(npath, bak)
        print(f"\n已備份原檔 → {bak}")
    nodes.to_csv(npath, index=False)

    hit = (nodes.loc[is_sensor, "win_val_cur"] != 0).mean()
    print(f"寫回 {npath}")
    print(f"sensor 節點列 {int(is_sensor.sum())}，其中 win_val_cur 非零比例 {hit:.1%}")
    if hit < 0.9:
        print("⚠ 命中率偏低 —— 檢查 anomaly.log 是否涵蓋該場景的所有秒")


if __name__ == "__main__":
    main()
