#!/usr/bin/env python3
# =============================================================================
# build_graph.py ── 由 pcap + log 建出 GNN 可用的「每秒一張圖」資料集
# =============================================================================
# 圖的定義（節點=主機/端點，邊=TCP 連線）：
#
#   節點 = OPC UA 端點（由 (ip, port) 身分推導出角色）
#       agg_server(:4840) · sensor_server(:4842) · motor1/2/3 · anomaly_client
#       attacker(匿名，攻擊時才出現)
#   邊   = 該秒內兩端點之間有 TCP 流量，邊特徵 = 該秒的流量統計
#
# 為什麼這個圖對偵測有意義：
#   四種攻擊在應用層各自隱蔽，但在**連線結構**上都是「多出一個端點/一條邊」。
#   GNN 的長處正是「結構 + 節點特徵」聯合建模，比單看每秒總量的向量更有資訊：
#   總量特徵會把「誰在說話」壓掉，而圖保留了它。
#
# 時間對齊：
#   pcap 的封包時間與 log 的行時間都換算成整數 epoch 秒，以「秒」為單位對齊。
#   節點特徵同時吃兩邊：流量（來自 pcap）+ 應用層行為（來自 log 的 SourceNode）。
#
# 標籤：
#   逐秒標籤（graph-level）：該秒有攻擊注入 → 1
#   逐節點標籤（node-level）：該秒該節點是攻擊者 → 1
#   兩種標籤都輸出，因為 GNN 可以做 graph classification 或 node classification。
#
# 輸出（<capture_dir>/graph/）：
#   nodes.csv    每秒每節點一列：node 特徵 + node 標籤
#   edges.csv    每秒每邊一列：edge 特徵
#   graphs.csv   每秒一列：graph 標籤與摘要
#   meta.json    節點字典、特徵名稱、統計
#
# 執行： ml/venv/bin/python net/build_graph.py net/captures/topo_3motor_<STAMP>
# =============================================================================
import os, sys, json, re
from collections import defaultdict

try:
    from scapy.all import PcapReader, TCP, IP, IPv6
except Exception as e:
    sys.exit(f"需要 scapy：ml/venv/bin/pip install scapy（{e}）")

import pandas as pd

AGG_PORT, SENSOR_PORT = 4840, 4842
# 多 sensor 拓撲（項目 2）：sensor i 監聽 4841+i，即 4842, 4843, ...
# 這裡先給一個涵蓋範圍，實際有哪幾個 port 由 pcap 決定（見 build_scenario）。
SENSOR_PORT_RANGE = set(range(4842, 4842 + 64))
SERVER_PORTS = {AGG_PORT} | SENSOR_PORT_RANGE


def sensor_node_name(port):
    """sensor port → 圖節點名。4842（第一台）沿用舊名 sensor_server，
    確保舊資料/舊報告的節點名不變；4843 以後為 sensor_server2/3..."""
    i = port - 4841
    return "sensor_server" if i == 1 else f"sensor_server{i}"

# 攻擊場景資料夾 → 攻擊類別
SCEN_KIND = {"benign": None, "S": "S", "T": "T", "R": "R", "RP": "RP", "all": "all"}


# =============================================================================
# 1) 端點身分解析
# =============================================================================
# 難點：pcap 只看得到 (ip, port)，看不到「這個 client 是 motor1 還是 motor2」。
# 解法：用 log 端的 SourceNode 得知「有哪些具名來源」，再用**連線行為特徵**
#   把 client port 對應到角色。本機全部走 loopback，IP 都是 127.0.0.1，
#   所以角色只能靠「連到哪個 server port + 連線模式」區分：
#
#     連到 4842（sensor）且長時間持續  → motor（訂閱者）
#     連到 4840（agg）且長時間持續     → motor 的 syslog 通道 / sensor 的 syslog / anomaly
#     短命、只在注入秒出現             → attacker（匿名）
#
# ⚠️ 誠實的限制：loopback 上**無法**從封包本身區分 motor1/2/3（它們的封包長得
#   一模一樣，只有隨機 client port 不同）。因此本腳本把 motor 群體建成
#   「依 client port 分開的獨立節點」，並用 log 的 SourceNode 統計去驗證數量吻合，
#   但**不宣稱**某個 port 就是 motor2。要真正逐台對應需跨主機部署（不同 IP）
#   或在應用層加上可觀測的識別（見報告的限制章節）。
def role_of(server_port, lifetime, n_pkts, total_secs, pkt_rank,
            src_ip="127.0.0.1", has_bound_srcs=False):
    """依連線行為推斷角色。

    實測的連線結構（S 場景，610 秒）：
        3 條 →4842 長命    = 三台 motor 訂閱 sensor
        5 條 →4840 長命    = 3×motor syslog + sensor syslog + Anomaly_client 讀取
                             （Anomaly_client 封包量明顯最大：6381 vs ~1840）
        1 條 →4840 短命 8s = 攻擊者（匿名注入）

    判定依據刻意只用「連線壽命 + 流量」這類**結構特徵**，不看 payload 內容，
    與 net/README.md 的方法學一致（不解 OPC UA binary，跨版本穩健）。
    """
    # ✅ 最可靠的依據：專屬來源 IP。
    # 採集時若掛了 net/bindsrc.so，每台 motor 綁定 127.0.0.2/.3/.4，
    # 這是**確定性**的身分，不必再靠壽命/流量這類啟發式去猜。
    # （沒掛 shim 的舊資料 src_ip 都是 127.0.0.1 → 落到下方的啟發式判定。）
    if src_ip != "127.0.0.1" and server_port in SENSOR_PORT_RANGE:
        return "motor"

    # 短命 = 壽命遠短於場景長度 → 攻擊者的一次性注入連線。
    # ⚠️ 門檻必須是**相對**的：寫死 30 秒會讓 25 秒的短採集把「全程存活的真 motor」
    # 判成攻擊者（實測踩過）。用場景長度的比例才對短/長採集都成立。
    if lifetime <= max(3, total_secs * 0.2):
        return "attacker"

    # ⚠️ 光看「壽命長」不夠：aggregation_server 也會連 sensor@4842，而且它的
    # 非阻塞重連（見 aggregation_server.c 註解）會留下少數幾秒、十來個封包的
    # 殘存連線。實測 benign：三台 motor 各 5426 封包/1800秒，這條只有 12 封包/4秒。
    # 若只用壽命判定，它會在長場景被誤認成第 4 台 motor。
    #
    # 因此 motor 另外要求「持續有流量」。門檻用**相對於場景長度**的比例，
    # 不用固定封包數 —— 固定門檻（如 >=60）會讓短採集（如 25 秒的煙霧測試）
    # 把真 motor 判成 transient，實測已踩過這個坑。
    # 真 motor：每秒都收到訂閱通知（~3 封包/秒）；殘存連線：整條僅十來個封包。
    sustained = (lifetime >= max(5, total_secs * 0.5)) and (n_pkts >= lifetime)
    if server_port in SENSOR_PORT_RANGE:
        # 走到這裡代表 src_ip == 127.0.0.1（沒掛 shim，或這條不是 motor）。
        # 若本次採集**有**掛 shim（has_bound_srcs），motor 一定帶專屬 IP，
        # 所以 127.0.0.1 連 4842 的必然不是 motor —— 實測是 T 竄改攻擊（打 4842）
        # 或 aggregation_server 的重連殘存。此時不可再用啟發式把它判成 motor。
        if has_bound_srcs:
            return "transient_client"
        return "motor" if sustained else "transient_client"
    # 連 4840 的長命連線：封包量最大的那條是 Anomaly_client（持續讀取整份 log）
    return "anomaly_client" if pkt_rank == 0 else "log_writer"


def _ips(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


# =============================================================================
# 2) pcap → 每秒每連線的流量
# =============================================================================
def read_pcap(path):
    """回傳 per[(sec, client_key, server_port)] = 流量統計，以及連線的生命期資訊。"""
    per = defaultdict(lambda: {"n_pkts": 0, "n_c2s": 0, "n_s2c": 0,
                               "b_c2s": 0, "b_s2c": 0, "n_syn": 0,
                               "n_finrst": 0, "max_payload": 0})
    conn_secs = defaultdict(set)
    conn_pkts = defaultdict(int)

    with PcapReader(path) as rd:
        for pkt in rd:
            if TCP not in pkt:
                continue
            ips = _ips(pkt)
            if ips is None:
                continue
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            to_server = dport in SERVER_PORTS
            from_server = sport in SERVER_PORTS
            if not (to_server or from_server):
                continue

            t = int(float(pkt.time))
            payload = len(bytes(tcp.payload))
            flags = tcp.flags
            if to_server:
                client_key, server_port = (ips[0], sport), dport
            else:
                client_key, server_port = (ips[1], dport), sport

            conn = (client_key, server_port)
            k = (t, client_key, server_port)
            d = per[k]
            d["n_pkts"] += 1
            d["max_payload"] = max(d["max_payload"], payload)
            if flags & 0x02: d["n_syn"] += 1
            if flags & 0x01 or flags & 0x04: d["n_finrst"] += 1
            if to_server:
                d["n_c2s"] += 1; d["b_c2s"] += payload
            else:
                d["n_s2c"] += 1; d["b_s2c"] += payload

            conn_secs[conn].add(t)
            conn_pkts[conn] += 1
    return per, conn_secs, conn_pkts


# =============================================================================
# 3) log → 每秒的應用層行為（節點特徵 + 攻擊秒標籤）
# =============================================================================
_TS = re.compile(r"\[(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3}) "
                 r"\(UTC([+-]\d{2})?(\d{2})?\)\]")

def _epoch(line):
    """把 log 行的時間戳換算成整數 epoch 秒（正確處理 (UTC) 與 (UTC+0800)）。"""
    m = _TS.search(line)
    if not m:
        return None
    from datetime import datetime, timezone, timedelta
    y, mo, d, h, mi, s, ms = (int(m.group(i)) for i in range(1, 8))
    off_h, off_m = m.group(8), m.group(9)
    if off_h is None:
        tz = timezone.utc
    else:
        sign = 1 if off_h[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=abs(int(off_h)), minutes=int(off_m or 0)))
    return int(datetime(y, mo, d, h, mi, s, tzinfo=tz).timestamp())


def _epoch_ms(line):
    """同 _epoch，但回傳**含毫秒**的浮點 epoch 秒。用於跨節點值對齊：
    motor 回報與 sensor 真值只對齊到「整數秒」時，sensor 值一秒內大幅擺動會造成
    一個 sample 的錯位 → 假偏差（見 all 場景 MotorSource2 lag 假象）。改用毫秒
    時間戳把每筆 motor 回報對到**時間上最接近**的 sensor 樣本，可消除此假象。"""
    m = _TS.search(line)
    if not m:
        return None
    from datetime import datetime, timezone, timedelta
    y, mo, d, h, mi, s, ms = (int(m.group(i)) for i in range(1, 8))
    off_h, off_m = m.group(8), m.group(9)
    if off_h is None:
        tz = timezone.utc
    else:
        sign = 1 if off_h[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=abs(int(off_h)), minutes=int(off_m or 0)))
    return datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=tz).timestamp()


def read_log(anomaly_log):
    """回傳 (每秒每來源的行數, 攻擊秒集合)。

    攻擊秒的判定用**伺服器端證據**，而非攻擊程式的 stdout（格式會變、可能缺漏）。
    三種證據：

      (0) 訊息含 " #MAL" 記號 → **進階攻擊的權威 ground truth**。
          stealth_spoof 與 compromised_node 每秒都寫（藏進正常節奏），只有真正
          惡意的那幾筆帶此記號。這是唯一能精準標「惡意秒」而非「攻擊者存在秒」
          的依據 —— 舊的 SourceNode=null 判定對它們會失效：
            · stealth_spoof：每秒都 null（含大量正常掩護寫入）→ 全標會過度
            · compromised_node：用合法 session → 從不 null → 全漏
          記號是評估專用通道，真實偵測器看不到（見攻擊原始碼註解）。
      (1) SourceNode = null   → 匿名寫入（舊版 S / R / RP）
      (2) BadUserAccessDenied → T 竄改（已認證 session 對唯讀節點寫入被拒）

    ⚠️ 取 SourceNode 必須取**最後一個**：RP 重放會把「連同伺服器舊蓋章一起複製」
    的整行重送 → 一行兩個 SourceNode= 欄位，伺服器的蓋章永遠在最後。

    ⚠️ 若場景中出現任何 #MAL 記號，**只用記號判定攻擊秒**（進階攻擊模式），
    不再混用 null/denied —— 否則 stealth 的每秒 null 掩護寫入會被全部誤標。
    """
    per_sec_src = defaultdict(lambda: defaultdict(int))
    mal_secs, null_secs, denied_secs = set(), set(), set()
    # 每秒 BadUserAccessDenied 行數：T 竄改的規則偵測器（router_fusion.py）要用。
    # 只計數、不參與標籤，標籤仍照 #MAL / null|denied 的既有規則。
    denied_counts = defaultdict(int)
    # (sec, sourcenode) → 該秒該來源是否有惡意寫入。供進階攻擊精準標到「哪個節點」。
    mal_by_src = set()
    # ---- 項目 B：跨節點值一致性（毫秒對齊版）----
    # compromised_node 攻擊在網路層完全正常（合法身分、正常流量、無多餘連線），
    # 唯一破綻是「這台 motor 回報的距離值 ≠ sensor 實際送出的值」。這是**跨節點**
    # 的語意一致性，單看一條邊/一個節點自身流量都看不到。
    #
    # ⚠️ 對齊必須用**毫秒**，不能用整數秒。sensor 值一秒內會大幅擺動，若把某台
    #   motor 的回報拿去跟「同一整數秒的 sensor log」比，只要兩者取樣差一個
    #   sample（常見的訂閱抖動），就會算出巨大的假偏差（曾在 all 場景看到 honest
    #   motor 因 lag 造成 spread=41，完全不是竄改）。改法：蒐集所有 sensor 樣本的
    #   (毫秒時間戳, 值)，每筆 motor 回報對到**時間上最接近**的 sensor 樣本再算差。
    #
    # 產出（皆以整數秒 t 索引，供掛到對應的圖節點/秒）：
    #   report_by_src[t][sourcenode] = 該秒該來源最後一次回報的距離
    #   report_dev_src[t][sourcenode]= 該回報與時間最近 sensor 樣本的偏差
    #   sensor_truth[t]              = 該整數秒最後一個 sensor 樣本值（僅供顯示/相容）
    report_by_src = defaultdict(dict)
    report_dev_src = defaultdict(dict)
    sensor_truth = {}
    sensor_truth_src = defaultdict(dict)     # t → {sensor SourceNode: 該秒最後一個值}
    sensor_samples = []            # [(epoch_ms, value)]，全部 sensor 混在一起
    # 多 sensor 拓撲（項目 2）：另外分來源保存，才能算「對**自己那台** sensor 的偏差」。
    # 注意兩者的意義完全不同，也是項目 2 的實驗核心：
    #   report_dev      = 對「**任一台** sensor 的最近樣本」的最小偏差 → 全域平特徵
    #   report_dev_own  = 對「該 motor **實際訂閱的那台** sensor」的偏差 → 需要拓撲
    # compromised_group 攻擊回報的是「別群 sensor 的真值」→ 前者=0（失效）、後者>0。
    sensor_samples_by_src = defaultdict(list)
    motor_reports = []             # [(epoch_ms, int_sec, src, value)]
    RE_MOTOR = re.compile(r"\[Motor\] Received distance:\s*([-+0-9.eE]+)")
    RE_SENSOR = re.compile(r"\[Sensor\] Updated distance:\s*([-+0-9.eE]+)")
    raw = dict(motor_reports=motor_reports,
               sensor_samples_by_src=sensor_samples_by_src,
               sensor_truth_src=sensor_truth_src)
    if not os.path.exists(anomaly_log):
        return (per_sec_src, mal_secs, mal_by_src,
                report_by_src, report_dev_src, sensor_truth, denied_counts, raw)
    for ln in open(anomaly_log, encoding="utf-8", errors="replace"):
        if "[Anomaly Input]" not in ln:
            continue
        t = _epoch(ln)
        if t is None:
            continue
        found = re.findall(r"SourceNode=(\S+)", ln)
        src = found[-1] if found else "unknown"      # 取最後一個 = 伺服器蓋的
        per_sec_src[t][src] += 1
        if "#MAL" in ln:
            mal_secs.add(t)
            mal_by_src.add((t, src))                  # 記下惡意來源，供邊標籤精準對應
        if "BadUserAccessDenied" in ln:
            denied_counts[t] += 1
        if src in ("null", "unverified"):
            null_secs.add(t)
        elif "BadUserAccessDenied" in ln:
            denied_secs.add(t)
        # 解析回報/真值（毫秒時間戳，用於跨節點一致性特徵）
        tms = _epoch_ms(ln)
        m = RE_MOTOR.search(ln)
        if m and tms is not None:
            try:
                v = float(m.group(1))
                report_by_src[t][src] = v
                motor_reports.append((tms, t, src, v))
            except ValueError:
                pass
        else:
            s = RE_SENSOR.search(ln)
            if s and tms is not None:
                try:
                    sv = float(s.group(1))
                    sensor_truth[t] = sv
                    sensor_samples.append((tms, sv))
                    sensor_samples_by_src[src].append((tms, sv))
                    sensor_truth_src[t][src] = sv
                except ValueError:
                    pass

    # 每筆 motor 回報 → 與「最近一段時間窗內的 sensor 樣本」比對，取**數值最接近**者的偏差。
    #
    # ⚠️ 關鍵觀察（實測 log）：honest motor 回報的值是它收到的某個 sensor 值的**逐位元
    #   複製**（15 位小數完全相同）。因此正確的一致性判定是：
    #     honest  → 回報值 = 最近窗內某個 sensor 樣本 → min 偏差 == 0（精確）
    #     tampered→ 回報值 = sensor±20，不等於任何近期 sensor 樣本 → min 偏差大
    #   不能用「時間最近的單一 sensor 樣本」：publish 有突發性，時間最近的未必是 motor
    #   真正收到的那個，會對 honest 也算出假偏差（曾讓 benign/R/RP dev 高達 40）。
    #   改成「窗內數值最接近」：honest 一定命中 0，只有竄改才偏離。
    WIN_MS = 3.0        # 往回看 3 秒的 sensor 樣本（涵蓋訂閱抖動，又不會誤配到太舊的值）
    if sensor_samples:
        sensor_samples.sort()
        s_times = [x[0] for x in sensor_samples]
        import bisect
        for tms, t, src, v in motor_reports:
            hi = bisect.bisect_right(s_times, tms + 0.5)     # 容許回報略晚於樣本
            lo = bisect.bisect_left(s_times, tms - WIN_MS)
            window = sensor_samples[lo:hi]
            if window:
                report_dev_src[t][src] = min(abs(v - sv) for _, sv in window)

    # 有記號 → 進階攻擊，只信記號；否則用舊的 null/denied 判定
    attack_secs = mal_secs if mal_secs else (null_secs | denied_secs)
    return (per_sec_src, attack_secs, mal_by_src,
            report_by_src, report_dev_src, sensor_truth, denied_counts, raw)


# =============================================================================
# 4) 建圖
# =============================================================================
def _sensor_node_vals(sensor_truth_src, t, fallback=None):
    """該整數秒每台 sensor 的真值 → {sensor 節點名: 值}。

    抽成函式是為了讓「窗內樣本」(t−1 / t / t+1) 能重用同一段對應邏輯
    （見 build_scenario 裡 win_val_* 的說明）。`fallback` 只在單 sensor
    舊資料沒有 per-src 記錄時使用，維持既有行為。
    """
    d = {}
    for ssrc, sv in sensor_truth_src.get(t, {}).items():
        if ssrc.startswith("ns=1;s=SensorSource"):
            d["sensor_server" + ssrc.replace("ns=1;s=SensorSource", "")] = sv
    if not d and fallback is not None:
        d["sensor_server"] = fallback
    return d


def build_scenario(scen_dir, scen_name):
    pcaps = [f for f in os.listdir(scen_dir) if f.endswith(".pcap")]
    if not pcaps:
        return None
    pcap = os.path.join(scen_dir, pcaps[0])

    per, conn_secs, conn_pkts = read_pcap(pcap)
    (per_sec_src, attack_secs, mal_by_src,
     report_by_src, report_dev_src, sensor_truth, denied_counts, raw) = read_log(
        os.path.join(scen_dir, "anomaly.log"))
    if not per:
        return None

    # 連線 → 角色
    all_t = [t for (t, _, _) in per.keys()]
    total_secs = (max(all_t) - min(all_t) + 1) if all_t else 0
    # 連 4840 的長命連線中，封包量最大的那條 = Anomaly_client
    agg_long = [c for c, s in conn_secs.items()
                if c[1] == AGG_PORT and (max(s) - min(s) + 1) > max(30, total_secs * 0.1)]
    agg_long.sort(key=lambda c: -conn_pkts[c])
    pkt_rank = {c: i for i, c in enumerate(agg_long)}

    # 本次採集是否使用了 net/bindsrc.so（motor 帶專屬 loopback 來源 IP）
    has_bound_srcs = any(c[0][0] != "127.0.0.1" for c in conn_secs)

    roles = {}
    for conn, secs in conn_secs.items():
        _, server_port = conn
        lifetime = max(secs) - min(secs) + 1
        roles[conn] = role_of(server_port, lifetime, conn_pkts[conn],
                              total_secs, pkt_rank.get(conn, 99),
                              src_ip=conn[0][0], has_bound_srcs=has_bound_srcs)

    # ---- 輪換場景修正（3-4）----
    # role_of 的「短命 = 攻擊者」啟發式假設連線壽命短是異常。但輪換場景**刻意**
    # 讓每台 motor 每 ROTATE_SEC 秒重連一次，於是它們寫 log 到 4840 的通道
    # 壽命只有 120s / 1800s → 全部被誤判成 attacker（實測 benign 出現 90 個
    # 假 attacker 節點）。標籤本身不受影響（進階攻擊的 attacker_conns 是用 IP 判的），
    # 但節點會改名成 attacker_N，讓「20 個攻擊秒的資料集卻有上萬列 attacker 節點」
    # 這種看起來像洩漏的假象出現在摘要裡。
    #
    # 修正：來源 IP 已經有一條 motor 訂閱連線 → 這個 IP 是已知的 motor（或冒用它
    # 身分的攻擊者），它連 4840 的那條就是正常 log 通道，與壽命無關。
    # 匿名注入者（S/R/RP/T，走 127.0.0.1）與 stealth（專屬 IP 但沒有訂閱連線）
    # 都不符合這個條件 → 角色與既有資料集完全不變。
    _motor_ips = {c[0][0] for c, r in roles.items() if r == "motor"}
    for conn, r in roles.items():
        if r == "attacker" and conn[1] == AGG_PORT and conn[0][0] in _motor_ips:
            roles[conn] = "log_writer"

    # 哪些連線屬於攻擊者？
    #
    # ⚠️ 這裡踩過一個嚴重的標籤錯誤，務必理解：
    #   最初的條件是「非常駐角色 且 與攻擊秒重疊」。但**正常的 log 通道**
    #   （sensor / 三台 motor 各自寫 log 到 4840）在攻擊那一秒同樣在寫 log，
    #   於是它們全部被誤標成攻擊邊 —— 118 條「攻擊邊」裡有 94 條是假標籤。
    #   後果：標籤實際上變成「這一秒是不是有攻擊」而非「這條連線是不是攻擊者」，
    #   模型只要偵測「攻擊秒」就能拿到 recall 1.000，分數是假的。
    #
    # 正解：用**出現秒數**區分。實測（611 秒的場景）：
    #     正常 log 通道 / motor / anomaly：出現 610~611 秒（全程持續）
    #     攻擊者                        ：只出現 6~8 秒（僅注入的那幾秒）
    #   注意不能用「連線壽命」(max-min)，攻擊者的壽命也有 601 秒 —— 它連上後
    #   一直保持連線，只是絕大多數時間沒有流量。必須看**實際有流量的秒數**。
    ATTACKER_PRESENCE_RATIO = 0.5      # 出現秒數 < 場景長度的一半 → 非常駐
    advanced = bool(mal_by_src)        # 有 #MAL 記號 = 進階攻擊（stealth / compromised）

    if advanced:
        # 進階攻擊：攻擊者「每秒都寫」以消除指紋，所以「出現秒數少」的舊判定失效。
        # 改用來源 IP 鎖定：進階攻擊綁一個**專屬 loopback IP**（127.0.0.<N+1/+2>），
        # 這個 IP 既不是三台 motor（127.0.0.2/.3/.4 中實際在跑的），也不是
        # server 自身與正常 log 通道用的 127.0.0.1。
        # ⚠️ 踩過的坑：不能只寫「非 motor IP」——sensor 的 syslog 通道與
        #   Anomaly_client 都走 127.0.0.1，會被一起誤標（stealth 場景曾出現
        #   每秒 2 條攻擊邊）。必須明確排除 127.0.0.1。
        motor_ips = {conn[0][0] for conn, r in roles.items() if r == "motor"}
        attacker_conns = {
            c for c in conn_secs
            if c[1] == AGG_PORT                    # 寫 log 到彙整伺服器
            and c[0][0] != "127.0.0.1"             # 不是 server/正常通道的預設位址
            and c[0][0] not in motor_ips           # 不是三台 motor
            and (conn_secs[c] & attack_secs)       # 活躍秒與惡意秒重疊
        }
    else:
        attacker_conns = {
            c for c, secs in conn_secs.items()
            if roles[c] not in ("motor", "anomaly_client")
            and (secs & attack_secs)
            and len(secs) < max(2, total_secs * ATTACKER_PRESENCE_RATIO)
        }

    # 節點命名：server 端固定；client 端用 角色 + 穩定序號
    #   序號依「首次出現時間」排序 → 同一次採集內穩定可重現
    client_order = sorted(conn_secs.keys(), key=lambda c: (min(conn_secs[c]), str(c)))
    node_name = {}
    counters = defaultdict(int)
    for conn in client_order:
        r = roles[conn]
        ip = conn[0][0]
        # 若採集時用了 net/bindsrc.so，每台 motor 有專屬的 loopback 來源 IP
        # （127.0.0.2/.3/.4）→ 節點名可直接綁定到「哪一台」，跨場景穩定可對應。
        # 未使用時退回「角色_流水號」（同一次採集內穩定，但無法跨場景對應）。
        if r == "motor" and ip != "127.0.0.1":
            node_name[conn] = f"motor_{ip.rsplit('.', 1)[-1]}"   # 127.0.0.2 → motor_2
        else:
            counters[r] += 1
            node_name[conn] = f"{r}_{counters[r]}"

    # 本次採集實際出現的 server port（多 sensor 時會有 4842/4843/...）
    SERVER_NODE = {AGG_PORT: "agg_server"}
    for (_, _, sp) in per.keys():
        if sp in SENSOR_PORT_RANGE:
            SERVER_NODE[sp] = sensor_node_name(sp)

    # ---- 項目 B：SourceNode → 圖節點名 的對應 ----
    # 目的：把「每台 motor 該秒回報的距離值」掛成該 motor **節點自身**的特徵，
    #   讓 GNN 能透過訊息傳遞（motor↔sensor↔agg）自己比對出「誰報的值不一致」，
    #   而不是靠我在 agg_server 上預先算好的 report_dev_max（那等於幫模型做完工）。
    #   對應規則來自 capture_topo.sh 的啟動慣例：
    #     motor_id=i → 綁 IP 127.0.0.(i+1) → 節點名 motor_(i+1)
    #     session 名：id 1 → "MotorSource"；id i → "MotorSource{i}"
    #   ⚠️ 只有採集時用了 bindsrc.so（每台 motor 專屬 IP）才能穩定對應；否則留空，
    #      per-node 值特徵全 0，退回只用 agg_server 的聚合特徵。
    src2node = {}
    if has_bound_srcs:
        for conn, nm in node_name.items():
            if roles.get(conn) == "motor" and nm.startswith("motor_"):
                last = nm.rsplit("_", 1)[-1]            # motor_3 → "3"
                try:
                    mid = int(last) - 1                 # IP .3 → motor_id 2
                except ValueError:
                    continue
                sess = "ns=1;s=MotorSource" if mid == 1 else f"ns=1;s=MotorSource{mid}"
                src2node[sess] = nm

    # ---- 項目 2：每台 motor 訂閱哪一台 sensor（由 pcap 直接觀察，不是設定檔）----
    # motor 的連線目的 port 就是它訂閱的 sensor（4841+i）。這個對應關係是
    # **拓撲資訊**：GNN 從訂閱邊本來就看得到，但要做成平特徵就得像這裡一樣人工編碼。
    #   node2sensor : motor 節點名 → sensor 節點名
    #   sess2sensor : motor SourceNode → 該 sensor 的 SourceNode（供算 report_dev_own）
    node2sensor, sess2sensor = {}, {}
    for conn, nm in node_name.items():
        if roles.get(conn) == "motor" and conn[1] in SENSOR_PORT_RANGE:
            node2sensor[nm] = sensor_node_name(conn[1])
    node2sess = {v: k for k, v in src2node.items()}
    for nm, sn in node2sensor.items():
        if nm in node2sess:
            i = 1 if sn == "sensor_server" else int(sn.replace("sensor_server", ""))
            sess2sensor[node2sess[nm]] = ("ns=1;s=SensorSource" if i == 1
                                          else f"ns=1;s=SensorSource{i}")

    # report_dev_own：只跟**自己訂閱的那台** sensor 的樣本比（其餘邏輯同 report_dev）。
    # 單 sensor 拓撲下它與 report_dev 完全相同；多 sensor 下兩者分道揚鑣 ——
    # compromised_group 攻擊正是靠這個差別才「平特徵看不見、拓撲看得見」。
    report_dev_own_src = defaultdict(dict)
    _samples_own = {k: sorted(v) for k, v in raw["sensor_samples_by_src"].items()}
    if _samples_own:
        import bisect as _bisect
        for tms, t, src, v in raw["motor_reports"]:
            sensor_src = sess2sensor.get(src)
            win = _samples_own.get(sensor_src)
            if not win:
                continue
            times = [x[0] for x in win]
            hi = _bisect.bisect_right(times, tms + 0.5)
            lo = _bisect.bisect_left(times, tms - 3.0)
            w = win[lo:hi]
            if w:
                report_dev_own_src[t][src] = min(abs(v - sv) for _, sv in w)

    # ---- 3-4：逐秒動態訂閱表 + report_dev_own_dyn（誠實的強基線）----
    # 上面的 sess2sensor 是一張**全域靜態**表（last-wins）。訂閱關係一旦輪換，
    # 它在絕大部分時間是錯的，而且**不會報錯**（靜默失效）—— 這正是 3-4 要量的東西。
    # 這裡另外算一個逐秒重建對照表的版本：每一秒從 pcap 觀察「該 motor 這秒
    # 實際連到哪個 sensor port」，沒有觀察到就沿用上一次觀察（forward-fill）。
    # 它是規則方的**最佳可能實作**，用來誠實界定主張的範圍：
    #   report_dev_own      崩掉  → 靜態拓撲模型會靜默失效
    #   report_dev_own_dyn  仍有效 → 規則做得到，但代價是必須逐秒維護一份正確拓撲
    # GNN 的差別在於它從當下這一秒的訂閱邊做訊息傳遞，不需要任何對照表。
    def _sensor_sess_of_port(sp):
        i = sp - 4841
        return "ns=1;s=SensorSource" if i == 1 else f"ns=1;s=SensorSource{i}"

    # t → {motor 節點名: {sensor SourceNode: 該秒封包數}}；同一秒可能同時有
    # 舊連線的收尾與新連線的建立（輪換邊界），取封包數較多的那條為當秒訂閱。
    _obs = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for (tt, ck, sp), d in per.items():
        if sp not in SENSOR_PORT_RANGE:
            continue
        conn = (ck, sp)
        if roles.get(conn) != "motor":
            continue
        nm = node_name.get(conn, "")
        if nm.startswith("motor_"):
            _obs[tt][nm][_sensor_sess_of_port(sp)] += d["n_pkts"]

    # forward-fill 成 t → {motor 節點名: sensor SourceNode}
    sess2sensor_dyn = {}          # t → {motor SourceNode: sensor SourceNode}
    _cur = {}
    for tt in sorted({t for (t, _, _) in per.keys()}):
        for nm, cand in _obs.get(tt, {}).items():
            _cur[nm] = max(cand.items(), key=lambda kv: kv[1])[0]
        sess2sensor_dyn[tt] = {sess: _cur[nm] for sess, nm in src2node.items()
                               if nm in _cur}

    report_dev_own_dyn_src = defaultdict(dict)
    if _samples_own:
        import bisect as _bisect
        for tms, t, src, v in raw["motor_reports"]:
            sensor_src = sess2sensor_dyn.get(t, {}).get(src)
            win = _samples_own.get(sensor_src)
            if not win:
                continue
            times = [x[0] for x in win]
            hi = _bisect.bisect_right(times, tms + 0.5)
            lo = _bisect.bisect_left(times, tms - 3.0)
            w = win[lo:hi]
            if w:
                report_dev_own_dyn_src[t][src] = min(abs(v - sv) for _, sv in w)

    # 診斷：靜態表與逐秒表在多少比例的秒上不一致（=靜態表的靜默失效率）
    _n_cmp = _n_bad = 0
    for tt, m in sess2sensor_dyn.items():
        for sess, sn in m.items():
            _n_cmp += 1
            if sess2sensor.get(sess) != sn:
                _n_bad += 1
    topo_static_mismatch = (_n_bad / _n_cmp) if _n_cmp else 0.0

    node_rows, edge_rows, graph_rows = [], [], []
    all_secs = sorted({t for (t, _, _) in per.keys()})

    for t in all_secs:
        # 該秒的所有邊
        items = [(ck, sp, d) for (tt, ck, sp), d in per.items() if tt == t]
        if not items:
            continue
        node_acc = defaultdict(lambda: defaultdict(float))
        n_attacker_edges = 0
        atk_nodes_this_sec = set()          # 該秒確實在注入的節點名

        for ck, sp, d in items:
            conn = (ck, sp)
            cname = node_name.get(conn, "unknown")
            sname = SERVER_NODE.get(sp, f"server_{sp}")
            # 攻擊者身分 × 該秒確實有注入 → 才算攻擊邊（避免把潛伏中的連線標成異常）。
            # 進階攻擊（有 #MAL）：該秒必須是「惡意秒」而非只是攻擊者活躍秒 ——
            # stealth 每秒都寫，只有 mal 秒才是真異常。attack_secs 在進階模式下
            # 已只含惡意秒（見 read_log），故此處條件對兩種模式都正確。
            is_atk = int(conn in attacker_conns and t in attack_secs)
            n_attacker_edges += is_atk
            if is_atk:
                atk_nodes_this_sec.add(cname)

            edge_rows.append(dict(
                scenario=scen_name, sec=t, src=cname, dst=sname,
                server_port=sp, role=roles.get(conn, "unknown"),
                n_pkts=d["n_pkts"], n_c2s=d["n_c2s"], n_s2c=d["n_s2c"],
                bytes_c2s=d["b_c2s"], bytes_s2c=d["b_s2c"],
                n_syn=d["n_syn"], n_finrst=d["n_finrst"],
                max_payload=d["max_payload"],
                is_attacker_edge=is_atk,
            ))
            # 邊的流量累加到兩端節點
            for nm in (cname, sname):
                acc = node_acc[nm]
                acc["n_pkts"] += d["n_pkts"]
                acc["bytes_c2s"] += d["b_c2s"]
                acc["bytes_s2c"] += d["b_s2c"]
                acc["n_syn"] += d["n_syn"]
                acc["n_finrst"] += d["n_finrst"]
                acc["max_payload"] = max(acc["max_payload"], d["max_payload"])
                acc["degree"] += 1

        # 應用層特徵：該秒各 SourceNode 的 log 行數，掛到對應的 server 節點
        log_counts = per_sec_src.get(t, {})
        n_log_null = sum(v for k, v in log_counts.items() if k in ("null", "unverified"))
        n_log_named = sum(v for k, v in log_counts.items() if k not in ("null", "unverified"))

        # ---- 項目 B：跨節點值一致性特徵（該秒，毫秒對齊）----
        # 動機：compromised_node 唯一破綻是「某台 motor 回報值 ≠ sensor 真值」。
        #   偏差用**毫秒對齊**算好（read_log 的 report_dev_src）：每筆回報對到時間
        #   最近的 sensor 樣本，避免整數秒錯位造成的假偏差（見 read_log 說明）。
        #     report_dev_max = max_i (毫秒對齊)|report_i − nearest_sensor|
        #     report_spread  = max_i report_i − min_i report_i   （motor 之間的分歧）
        #   正常時每台 motor 都準確轉報 → dev≈0；被入侵那秒竄改的 motor dev 明顯 >0。
        #   這是**跨節點聚合**才看得到的訊號，單邊分類拿不到。
        reps = report_by_src.get(t, {})
        devs = report_dev_src.get(t, {})
        devs_own = report_dev_own_src.get(t, {})
        devs_own_dyn = report_dev_own_dyn_src.get(t, {})
        truth = sensor_truth.get(t)      # 該整數秒最後一個 sensor 值（掛給 sensor 節點）
        rvals = [v for k, v in reps.items() if k not in ("null", "unverified", "unknown")]
        dvals = [v for k, v in devs.items() if k not in ("null", "unverified", "unknown")]
        # 每個 motor 節點該秒的回報值 & 毫秒對齊的偏差（per-node 特徵）
        node_report = {}       # node_name → 回報值
        node_dev = {}          # node_name → 毫秒對齊 |回報值 − 最近 sensor 樣本|
        node_dev_own = {}      # node_name → 只跟自己訂閱的 sensor 比的偏差（靜態表）
        node_dev_own_dyn = {}  # node_name → 同上，但對照表是逐秒重建的（3-4）
        for sess, nm in src2node.items():
            if sess in reps:
                node_report[nm] = reps[sess]
            if sess in devs:
                node_dev[nm] = devs[sess]
            if sess in devs_own:
                node_dev_own[nm] = devs_own[sess]
            if sess in devs_own_dyn:
                node_dev_own_dyn[nm] = devs_own_dyn[sess]
        dvals_own = [v for k, v in devs_own.items()
                     if k not in ("null", "unverified", "unknown")]
        report_dev_own_max = max(dvals_own) if dvals_own else 0.0
        dvals_own_dyn = [v for k, v in devs_own_dyn.items()
                         if k not in ("null", "unverified", "unknown")]
        report_dev_own_dyn_max = max(dvals_own_dyn) if dvals_own_dyn else 0.0
        report_dev_max = max(dvals) if dvals else 0.0
        report_spread = (max(rvals) - min(rvals)) if rvals else 0.0

        # 每個 sensor 節點掛自己的真值（多 sensor 時各掛各的；單 sensor 時同舊行為）
        sensor_node_val = _sensor_node_vals(raw["sensor_truth_src"], t, truth)
        # ---- 1:1 pair 拓撲用：sensor 節點的「窗內樣本」(t−1, t, t+1) ----
        # 為什麼需要（TOPO_PAIR3_GNN_DESIGN.md）：三組 1 對 1 下每台 motor 沒有同群
        # motor peer，鄰居只剩自己那台 sensor，於是 GNN 只能拿 sensor 節點的**該秒
        # 一個純量**來預測 motor 的回報值 —— 但 honest motor 抄的是**鄰近某一秒**的
        # 樣本，而這條序列每步就跳 ~13（實測 3s6m benign：相鄰樣本差中位 13.08）。
        # 同秒相減的 benign 雜訊（中位 13.8 / p95 37.3）比攻擊訊號（~20）還大 →
        # 一跳重建在原理上學不起來（實測 C 0.043 ≈ D 0.043，top1 ≈ 隨機）。
        # 掛上窗內三筆之後，honest 必定命中其中一筆（實測 benign min-dev 全 0.000），
        # 冒用者對三筆都差 18~26 → 訊號回來了。
        # ⚠️ 這三個欄位**只描述 sensor 自己**，不涉及任何 motor 的回報值，
        #    所以不是 report_dev 那種「答案外洩」。比對要由模型自己做。
        sensor_win_prev = _sensor_node_vals(raw["sensor_truth_src"], t - 1)
        sensor_win_next = _sensor_node_vals(raw["sensor_truth_src"], t + 1)

        for nm, acc in node_acc.items():
            # node 標籤 = 「該節點在這一秒確實注入」，不是「它是攻擊者」。
            # 後者會把攻擊者潛伏中的數千個正常秒也標成 1（洩漏）。
            is_atk_node = int(nm in atk_nodes_this_sec)
            node_rows.append(dict(
                scenario=scen_name, sec=t, node=nm,
                node_type=("server" if nm in SERVER_NODE.values() else nm.rsplit("_", 1)[0]),
                **{k: acc[k] for k in ["n_pkts", "bytes_c2s", "bytes_s2c",
                                       "n_syn", "n_finrst", "max_payload", "degree"]},
                # 應用層特徵（只有 agg_server 看得到 log 寫入）
                log_lines_named=(n_log_named if nm == "agg_server" else 0),
                log_lines_null=(n_log_null if nm == "agg_server" else 0),
                # 跨節點值一致性（只有彙整端能同時看到所有 motor 的回報）
                report_dev_max=(report_dev_max if nm == "agg_server" else 0.0),
                report_spread=(report_spread if nm == "agg_server" else 0.0),
                # per-node 值特徵：讓 GNN 自己透過訊息傳遞比對「誰報的值不一致」。
                #   motor 節點掛自己的回報值與對真值的偏差；sensor_server 掛真值。
                #   （agg_server / 其他節點為 0）
                report_val=(node_report.get(nm, 0.0) if nm.startswith("motor_")
                            else (sensor_node_val.get(nm, 0.0))),
                report_dev=(node_dev.get(nm, 0.0) if nm.startswith("motor_") else 0.0),
                report_dev_own=(node_dev_own.get(nm, 0.0) if nm.startswith("motor_") else 0.0),
                report_dev_own_dyn=(node_dev_own_dyn.get(nm, 0.0)
                                    if nm.startswith("motor_") else 0.0),
                # sensor 的窗內樣本（只掛在 sensor 節點上；其餘節點恆 0）
                win_val_prev=(sensor_win_prev.get(nm, sensor_node_val.get(nm, 0.0))
                              if nm.startswith("sensor_server") else 0.0),
                win_val_cur=(sensor_node_val.get(nm, 0.0)
                             if nm.startswith("sensor_server") else 0.0),
                win_val_next=(sensor_win_next.get(nm, sensor_node_val.get(nm, 0.0))
                              if nm.startswith("sensor_server") else 0.0),
                label=is_atk_node,
            ))

        graph_rows.append(dict(
            scenario=scen_name, sec=t,
            n_nodes=len(node_acc), n_edges=len(items),
            n_attacker_edges=n_attacker_edges,
            log_lines_named=n_log_named, log_lines_null=n_log_null,
            log_lines_denied=int(denied_counts.get(t, 0)),
            report_dev_max=report_dev_max, report_spread=report_spread,
            report_dev_own_max=report_dev_own_max,
            report_dev_own_dyn_max=report_dev_own_dyn_max,
            label=int(t in attack_secs),
        ))

    # ---- 時序特徵（項目3）----
    # 動機：目前每秒一張獨立的圖，完全沒用到跨秒動態。攻擊者的
    #   「潛伏→注入→潛伏」在單秒快照裡看不出來，但在時間軸上是明顯的突波。
    #   為每個節點加三個時序特徵（都只看該節點自己的歷史，不看未來 → 無洩漏）：
    #     d_n_pkts   : 與前一秒相比的封包數變化（突然說話/沉默）
    #     roll_mean  : 最近 W 秒的封包均值（該節點的常態流量水準）
    #     roll_std   : 最近 W 秒的封包標準差（行為是否穩定）
    #   這樣「一個平常穩定的節點突然改變」就有可分的數值訊號。
    W = 5
    hist = defaultdict(list)          # node → [(sec, n_pkts), ...] 按秒遞增
    # node_rows 已按 (sec) 遞增 append，同一 node 的順序即時間序
    for row in node_rows:
        nm = row["node"]
        prev = hist[nm]
        cur = row["n_pkts"]
        row["d_n_pkts"] = float(cur - prev[-1][1]) if prev else 0.0
        window = [v for (_, v) in prev[-W:]]
        if window:
            m = sum(window) / len(window)
            row["roll_mean"] = float(m)
            row["roll_std"] = float((sum((v - m) ** 2 for v in window) / len(window)) ** 0.5)
        else:
            row["roll_mean"] = float(cur)
            row["roll_std"] = 0.0
        prev.append((row["sec"], cur))

    # ---- 交叉驗證：從封包推出的拓撲，是否與 log 的 SourceNode 事實一致？----
    # 這一步是刻意加的：角色是「猜」出來的，若不對照就可能整份資料默默標錯。
    # 一致性檢查比的是「有幾台 motor」，不是「有幾條 motor 連線」——
    # 輪換場景（3-4）每台 motor 每個時段重連一次，連線數 = 台數 × 時段數，
    # 用連線數比會一直誤報 ⚠。靜態場景下兩者相同，故此改動不影響既有結果。
    n_motor_conn = len({node_name[c] for c, r in roles.items() if r == "motor"})
    srcs = set()
    for counts in per_sec_src.values():
        srcs |= {s for s in counts if s not in ("null", "unverified", "unknown")}
    n_motor_log = len({s for s in srcs if "Motor" in s})
    # 攻擊邊的合理性檢查：每個攻擊秒通常只有 1 條攻擊者連線在注入。
    # 若平均遠大於 1，多半是把同秒的正常通道也標進來了（曾發生過的標籤錯誤）。
    n_atk_edges = sum(1 for r in edge_rows if r["is_attacker_edge"] == 1)
    n_atk_secs_seen = len({(r["scenario"], r["sec"]) for r in edge_rows
                           if r["is_attacker_edge"] == 1})
    per_sec = (n_atk_edges / n_atk_secs_seen) if n_atk_secs_seen else 0.0

    check = dict(motor_conns=n_motor_conn, motor_sources_in_log=n_motor_log,
                 consistent=(n_motor_conn == n_motor_log),
                 attacker_conns=len(attacker_conns),
                 atk_edges=n_atk_edges, atk_edges_per_sec=round(per_sec, 2),
                 edges_per_sec_ok=(per_sec <= 2.0),
                 # 3-4：靜態 motor→sensor 對照表在多少比例的 (秒, motor) 上是錯的。
                 # 靜態拓撲場景應 ≈0；輪換場景應接近 (1 − 1/N_SENSOR)。
                 topo_static_mismatch=round(topo_static_mismatch, 4))

    return node_rows, edge_rows, graph_rows, len(attack_secs), check


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: build_graph.py <capture_dir>")
    root = os.path.abspath(sys.argv[1])
    outdir = os.path.join(root, "graph")
    os.makedirs(outdir, exist_ok=True)

    all_nodes, all_edges, all_graphs = [], [], []
    checks = {}
    print(f"建圖 ← {root}")
    for scen in sorted(os.listdir(root)):
        d = os.path.join(root, scen)
        if not os.path.isdir(d) or scen == "graph":
            continue
        res = build_scenario(d, scen)
        if res is None:
            print(f"  ⚠ {scen}: 無 pcap 或無流量，跳過")
            continue
        n, e, g, n_atk_sec, chk = res
        all_nodes += n; all_edges += e; all_graphs += g
        flag = "✓" if chk["consistent"] else "⚠"
        eflag = "✓" if chk["edges_per_sec_ok"] else "⚠"
        print(f"  ✓ {scen:8} 圖(秒)={len(g):5} 節點={len(n):6} 邊={len(e):6} "
              f"攻擊秒={n_atk_sec:3} {flag}motor={chk['motor_conns']}/{chk['motor_sources_in_log']} "
              f"{eflag}攻擊邊={chk['atk_edges']}({chk['atk_edges_per_sec']}/秒) "
              f"靜態拓撲錯誤率={chk['topo_static_mismatch']:.0%}")
        checks[scen] = chk

    if not all_graphs:
        sys.exit("沒有建出任何圖 —— 請確認採集目錄下有 <scen>/*.pcap")

    nodes = pd.DataFrame(all_nodes)
    edges = pd.DataFrame(all_edges)
    graphs = pd.DataFrame(all_graphs)
    nodes.to_csv(os.path.join(outdir, "nodes.csv"), index=False)
    edges.to_csv(os.path.join(outdir, "edges.csv"), index=False)
    graphs.to_csv(os.path.join(outdir, "graphs.csv"), index=False)

    meta = dict(
        capture_dir=root,
        n_graphs=int(len(graphs)),
        n_graphs_anomalous=int(graphs.label.sum()),
        anomaly_rate=float(graphs.label.mean()),
        n_node_rows=int(len(nodes)), n_edge_rows=int(len(edges)),
        node_types=nodes.node_type.value_counts().to_dict(),
        topology_check=checks,
        node_feature_cols=["n_pkts", "bytes_c2s", "bytes_s2c", "n_syn",
                           "n_finrst", "max_payload", "degree",
                           "log_lines_named", "log_lines_null",
                           "log_lines_denied",
                           "d_n_pkts", "roll_mean", "roll_std",   # 時序（項目3）
                           "report_dev_max", "report_spread",     # 跨節點聚合（項目B, agg_server）
                           "report_dev_own",                      # 對自己訂閱的 sensor（項目2，靜態表）
                           "report_dev_own_dyn",                  # 同上但逐秒重建對照表（3-4）
                           "report_val", "report_dev",            # per-node 值（項目B, 讓 GNN 自比對）
                           "win_val_prev", "win_val_cur",         # sensor 窗內樣本（1:1 pair 拓撲用）
                           "win_val_next"],
        edge_feature_cols=["n_pkts", "n_c2s", "n_s2c", "bytes_c2s", "bytes_s2c",
                           "n_syn", "n_finrst", "max_payload"],
        scenarios={s: dict(
            graphs=int((graphs.scenario == s).sum()),
            anomalous=int(graphs[graphs.scenario == s].label.sum()))
            for s in graphs.scenario.unique()},
    )
    with open(os.path.join(outdir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*70}")
    print("圖資料集摘要")
    print(f"{'='*70}")
    print(f"  圖數（每秒一張）: {meta['n_graphs']}   異常圖: {meta['n_graphs_anomalous']} "
          f"({meta['anomaly_rate']:.2%})")
    print(f"  節點列 / 邊列   : {meta['n_node_rows']} / {meta['n_edge_rows']}")
    print(f"  節點型別        : {meta['node_types']}")
    print(f"\n  逐場景：")
    for s, v in meta["scenarios"].items():
        print(f"    {s:8} 圖={v['graphs']:5}  異常={v['anomalous']:4}")
    print(f"\n輸出 → {outdir}/  (nodes.csv, edges.csv, graphs.csv, meta.json)")


if __name__ == "__main__":
    main()
