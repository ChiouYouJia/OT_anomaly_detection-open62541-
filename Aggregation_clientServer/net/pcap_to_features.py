#!/usr/bin/env python3
# =============================================================================
# pcap_to_features.py ── 把 pcap 轉成「每秒 flow 統計特徵」CSV（供 ML 用）
# =============================================================================
# 對應 capture_spoof.sh 抓到的 benign.pcap / spoof.pcap。
#
# 設計理念（為什麼是「每秒 flow 統計」而非逐封包分類）：
#   loopback 上的 OPC UA 未加密，但我們刻意*不*解 OPC UA binary payload
#   （那是 open62541 自訂序列化，工程量大且脆弱）。spoof 攻擊的破綻其實在
#   *流量結構*，不在單一封包內容：
#     - 攻擊者是「多出來的一個匿名 client」→ 多一條到 :4840 的 TCP 連線
#     - 它額外送 Write 請求 → 該秒 client→server 的封包數 / payload bytes 變多
#     - 稀疏注入 → 只有少數幾秒出現這種偏離（正是異常偵測的設定）
#   所以我們把流量聚合成「每秒一列」的統計特徵，讓無監督模型學正常秒的分布，
#   偏離的秒就是候選異常。
#
# 每秒特徵（皆只由封包標頭/大小得出，不解 payload）：
#   n_pkts            該秒總封包數
#   n_pkts_c2s        client→server 封包數（送往 :4840）
#   n_pkts_s2c        server→client 封包數（來自 :4840）
#   bytes_c2s         client→server payload 總位元組
#   bytes_s2c         server→client payload 總位元組
#   n_conns           該秒「活躍」的不同 TCP 連線數（依 5-tuple 的對端 port）
#   n_syn             該秒 SYN 數（新連線建立 → spoof client 連上時會出現）
#   n_fin_rst         該秒 FIN/RST 數（連線關閉）
#   uniq_client_ports 該秒出現過的不同 client 端 port 數（多一個攻擊者 → 變多）
#   max_payload       該秒單封包最大 payload（Write 請求通常較大）
#
# 標籤（label）：
#   benign.pcap 全部 label=0。
#   spoof.pcap 依 spoof_attack.log 的注入時間戳，把「有注入的那一秒」label=1，
#   其餘秒 label=0（真實比例：異常秒極少 → 不平衡，符合實務）。
#   若找不到攻擊 log，退而用「spoof.pcap 全標 0、只輸出特徵」供純無監督探索。
#
# 用法：
#   ml/venv/bin/python net/pcap_to_features.py net/captures/spoof_<STAMP>
# 輸出：該資料夾下 benign_flows.csv / spoof_flows.csv
# =============================================================================
import sys, os, re, csv
from collections import defaultdict
from datetime import datetime, timezone

try:
    from scapy.all import PcapReader, TCP, IP, IPv6
except Exception as e:
    sys.exit(f"需要 scapy：ml/venv/bin/pip install scapy（{e}）")

PORT = 4840                       # aggregation_server（S/R/RP 的目標）
SERVER_PORTS = {4840, 4842}       # 4842 = sensor_pub server（T 的目標）


def _l4(pkt):
    """回傳 (src_ip, dst_ip) 或 None（非 IP）。"""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def extract(pcap_path):
    """把 pcap 聚合成 {epoch_sec: feature_dict}。"""
    per_sec = defaultdict(lambda: {
        "n_pkts": 0, "n_pkts_c2s": 0, "n_pkts_s2c": 0,
        "bytes_c2s": 0, "bytes_s2c": 0,
        "n_syn": 0, "n_fin_rst": 0, "max_payload": 0,
        "_conns": set(), "_client_ports": set(),
    })
    with PcapReader(pcap_path) as rd:
        for pkt in rd:
            if TCP not in pkt:
                continue
            ips = _l4(pkt)
            if ips is None:
                continue
            t = int(float(pkt.time))
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            payload = len(bytes(tcp.payload))
            f = tcp.flags

            # 判斷方向：目標是某個 server port → client→server；來源是 → server→client。
            # 支援多個 server（4840 aggregation + 4842 sensor），涵蓋 T(4842)。
            to_server = dport in SERVER_PORTS
            from_server = sport in SERVER_PORTS
            if not (to_server or from_server):
                continue                       # 非 OPC UA server 流量，略過
            # 用「非 server 端」的 (ip,port) 當連線識別；區分不同 client / server。
            if to_server:
                client_key = (ips[0], sport)   # 送方是 client
                server_port = dport
            else:
                client_key = (ips[1], dport)   # 收方是 client
                server_port = sport

            d = per_sec[t]
            d["n_pkts"] += 1
            d["max_payload"] = max(d["max_payload"], payload)
            if f & 0x02:
                d["n_syn"] += 1
            if f & 0x01 or f & 0x04:
                d["n_fin_rst"] += 1
            # 連線識別加上 server_port，避免同一 client port 對不同 server 被併掉。
            conn_id = (client_key, server_port)
            d["_conns"].add(conn_id)
            d["_client_ports"].add(client_key)

            if to_server:
                d["n_pkts_c2s"] += 1
                d["bytes_c2s"] += payload
            else:
                d["n_pkts_s2c"] += 1
                d["bytes_s2c"] += payload

    rows = {}
    for t, d in per_sec.items():
        rows[t] = {
            "n_pkts": d["n_pkts"],
            "n_pkts_c2s": d["n_pkts_c2s"],
            "n_pkts_s2c": d["n_pkts_s2c"],
            "bytes_c2s": d["bytes_c2s"],
            "bytes_s2c": d["bytes_s2c"],
            "n_conns": len(d["_conns"]),
            "n_syn": d["n_syn"],
            "n_fin_rst": d["n_fin_rst"],
            "uniq_client_ports": len(d["_client_ports"]),
            "max_payload": d["max_payload"],
        }
    return rows


# spoof_attack.log 的注入行時間戳，例如：
#   ... injected (as Sensor): [2026-08-05 15:51:35.491 (UTC)] ...
#   ... injected (as Sensor): [2026-08-05 15:51:35.491 (UTC+0800)] ...
# 時區依系統 locale 可能是 (UTC) 或帶偏移 (UTC±HHMM)，兩者都要正確換算成 epoch，
# 否則標籤會對不上封包時間 → ground truth 永遠 0。
from datetime import timedelta
_TS_RE = re.compile(
    r"\[(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3}) "
    r"\(UTC([+-]\d{2})?(\d{2})?\)\]")


def injected_seconds(attack_log):
    """從 spoof_attack.log 取出每筆注入的『整數 epoch 秒』集合。"""
    secs = set()
    if not os.path.exists(attack_log):
        return secs
    for line in open(attack_log, encoding="utf-8", errors="replace"):
        if "injected" not in line:
            continue
        m = _TS_RE.search(line)
        if not m:
            continue
        y, mo, da, h, mi, s, _ms = (int(m.group(i)) for i in range(1, 8))
        off_h = int(m.group(8)) if m.group(8) else 0       # 例如 +08
        off_m = int(m.group(9)) if m.group(9) else 0        # 例如 00
        sign = 1 if off_h >= 0 else -1
        tz = timezone(timedelta(hours=off_h, minutes=sign * off_m))
        dt = datetime(y, mo, da, h, mi, s, tzinfo=tz)
        secs.add(int(dt.timestamp()))
    return secs


# anomaly.log 裡每行的內嵌時間戳（server 收到寫入時蓋的），例如：
#   [Anomaly Input] [2026-08-05 08:02:06.123 (UTC)] info/application	[Sensor] ...
_LINE_TS_RE = _TS_RE          # 同格式，重用


def _line_epoch(line):
    """從一行 log 取出內嵌時間戳的整數 epoch 秒；無則回 None。"""
    m = _LINE_TS_RE.search(line)
    if not m:
        return None
    y, mo, da, h, mi, s, _ms = (int(m.group(i)) for i in range(1, 8))
    off_h = int(m.group(8)) if m.group(8) else 0
    off_m = int(m.group(9)) if m.group(9) else 0
    sign = 1 if off_h >= 0 else -1
    tz = timezone(timedelta(hours=off_h, minutes=sign * off_m))
    return int(datetime(y, mo, da, h, mi, s, tzinfo=tz).timestamp())


def _iter_log(path):
    if os.path.exists(path):
        yield from open(path, encoding="utf-8", errors="replace")


def repudiation_seconds_from_server(anomaly_log):
    """R(否認)：攻擊冒充 motor 寫入『[Motor] ... rotating / Distance too close/safe』，
    但 server 蓋的 SourceNode=null（匿名）。取這些行的秒。
    ⚠️ 若程式未輸出 SourceNode（舊格式），此法無法標；退回 None 由上層決定。"""
    secs, saw_sourcenode = set(), False
    for line in _iter_log(anomaly_log):
        if "SourceNode=" in line:
            saw_sourcenode = True
        if "[Motor]" in line and "SourceNode=null" in line:
            e = _line_epoch(line)
            if e is not None:
                secs.add(e)
    return secs if saw_sourcenode else None


def tamper_seconds_from_server(anomaly_log, sensor_log):
    """T(篡改)：對唯讀節點寫入被拒 → 出現 BadUserAccessDenied。
    可能在 anomaly.log 或 sensor.log（4842）。取這些行的秒。"""
    secs = set()
    for path in (anomaly_log, sensor_log):
        for line in _iter_log(path):
            if "BadUserAccessDenied" in line:
                e = _line_epoch(line)
                if e is not None:
                    secs.add(e)
    return secs


def replay_seconds_from_server(anomaly_log):
    """RP(重放)：同一則『內容(含內嵌時間戳)完全相同』的 sensor/motor 事件再次出現。
    取『第 2 次(含)以後出現該內容』的那一秒。"""
    secs, seen = set(), set()
    for line in _iter_log(anomaly_log):
        if "[Anomaly Input]" not in line:
            continue
        # 內容本體 = 去掉外層 [Anomaly Input] 前綴與 server 蓋的 SourceNode 後綴
        body = line.split("[Anomaly Input]", 1)[-1]
        body = re.split(r"\s*\|\s*SourceNode=", body)[0]
        body = re.sub(r"\s+", " ", body).strip()
        if body in seen:
            e = _line_epoch(line)          # 重播寫入被收下的『那一秒』（新時間）
            if e is not None:
                secs.add(e)
        seen.add(body)
    return secs


def injected_seconds_from_server(anomaly_log):
    """從 server 端 anomaly.log 反推注入秒（不依賴會遺失的攻擊 stdout）。

    依據 spoof 的物理破綻：正常每秒最多一筆 sensor 讀數，攻擊者注入造成
    『同一秒出現 ≥2 筆 [Sensor] Updated distance』。把這些秒當注入秒。
    這是 server 自己收到的紀錄，即使攻擊程式被 kill -9 也不會遺失。
    """
    secs = set()
    if not os.path.exists(anomaly_log):
        return secs
    per_sec_cnt = defaultdict(int)
    for line in open(anomaly_log, encoding="utf-8", errors="replace"):
        if "Updated distance" not in line or "[Sensor]" not in line:
            continue
        m = _LINE_TS_RE.search(line)
        if not m:
            continue
        y, mo, da, h, mi, s, _ms = (int(m.group(i)) for i in range(1, 8))
        off_h = int(m.group(8)) if m.group(8) else 0
        off_m = int(m.group(9)) if m.group(9) else 0
        sign = 1 if off_h >= 0 else -1
        tz = timezone(timedelta(hours=off_h, minutes=sign * off_m))
        epoch = int(datetime(y, mo, da, h, mi, s, tzinfo=tz).timestamp())
        per_sec_cnt[epoch] += 1
    for epoch, c in per_sec_cnt.items():
        if c >= 2:                # 同秒雙報 → 注入秒
            secs.add(epoch)
    return secs


FIELDS = ["t_rel", "n_pkts", "n_pkts_c2s", "n_pkts_s2c", "bytes_c2s", "bytes_s2c",
          "n_conns", "n_syn", "n_fin_rst", "uniq_client_ports", "max_payload", "label"]


def write_csv(rows, out_path, label_secs=None):
    """rows: {epoch: feats}。label_secs: 需標 1 的 epoch 集合（None → 全 0）。
    t_rel 為相對第一秒的秒數，方便對齊/繪圖。"""
    if not rows:
        print(f"  ⚠ {os.path.basename(out_path)}：無 TCP 封包，跳過")
        return 0, 0
    t0 = min(rows)
    n_anom = 0
    with open(out_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for t in sorted(rows):
            r = dict(rows[t])
            r["t_rel"] = t - t0
            lbl = 1 if (label_secs and t in label_secs) else 0
            r["label"] = lbl
            n_anom += lbl
            w.writerow(r)
    print(f"  ✓ {os.path.basename(out_path)}：{len(rows)} 秒，異常秒 {n_anom}")
    return len(rows), n_anom


def detect_attack_kind(d):
    """依資料夾名稱判斷攻擊類型：spoof_/s_ → S；r_ → R；t_ → T；rp_ → RP；all_/four → ALL。"""
    b = os.path.basename(os.path.normpath(d)).lower()
    if b.startswith("rp_") or "replay" in b:
        return "RP"
    if b.startswith("r_") or "repud" in b:
        return "R"
    if b.startswith("t_") or "tamper" in b:
        return "T"
    if b.startswith("all_") or "four" in b or "combined" in b:
        return "ALL"
    return "S"                                  # 預設含 spoof_/s_


def ground_truth_seconds(d, kind):
    """回傳 (注入秒集合, 說明字串)。以 server 端紀錄為主，spoof 另有攻擊 stdout 佐證。"""
    anomaly = os.path.join(d, "anomaly.log")
    sensor = os.path.join(d, "sensor.log")
    if kind == "S":
        atk = injected_seconds(os.path.join(d, "spoof_attack.log"))
        srv = injected_seconds_from_server(anomaly)
        return atk | srv, f"S: 攻擊log={len(atk)} server端={len(srv)}"
    if kind == "R":
        srv = repudiation_seconds_from_server(anomaly)
        if srv is None:
            return set(), "R: ⚠ log 無 SourceNode 欄位，server 端無法標（R 本就難偵測）"
        return srv, f"R: server端(SourceNode=null 的[Motor])={len(srv)}"
    if kind == "T":
        srv = tamper_seconds_from_server(anomaly, sensor)
        return srv, f"T: server端(BadUserAccessDenied)={len(srv)}"
    if kind == "RP":
        srv = replay_seconds_from_server(anomaly)
        return srv, f"RP: server端(重複內容)={len(srv)}"
    if kind == "ALL":
        s = injected_seconds(os.path.join(d, "spoof_attack.log")) | injected_seconds_from_server(anomaly)
        r = repudiation_seconds_from_server(anomaly) or set()
        t = tamper_seconds_from_server(anomaly, sensor)
        rp = replay_seconds_from_server(anomaly)
        allsec = s | r | t | rp
        return allsec, f"ALL: S={len(s)} R={len(r)} T={len(t)} RP={len(rp)} 聯集={len(allsec)}"
    return set(), "未知類型"


def main():
    if len(sys.argv) < 2:
        sys.exit("用法：pcap_to_features.py <capture_dir>")
    d = sys.argv[1]
    benign = os.path.join(d, "benign.pcap")
    # 相容兩種命名：capture_attacks.sh 產 attack.pcap；capture_spoof.sh 產 spoof.pcap
    attack = os.path.join(d, "attack.pcap")
    if not os.path.exists(attack):
        attack = os.path.join(d, "spoof.pcap")
    if not os.path.exists(benign) or not os.path.exists(attack):
        sys.exit(f"找不到 benign.pcap / attack.pcap(或 spoof.pcap) 於 {d}")

    kind = detect_attack_kind(d)
    print(f"[feat] 攻擊類型（依資料夾名）：{kind}")

    print(f"[feat] 解析 {benign}")
    write_csv(extract(benign), os.path.join(d, "benign_flows.csv"))

    print(f"[feat] 解析 {attack}")
    inj, desc = ground_truth_seconds(d, kind)
    print(f"[feat] ground truth 注入秒 → {desc}")
    if not inj:
        print("[feat] ⚠ 取不到注入秒 → attack 全標 0（僅供無監督探索；對 R 屬預期結果）")
    write_csv(extract(attack), os.path.join(d, "spoof_flows.csv"), label_secs=inj)

    print(f"[feat] 完成 → {d}/benign_flows.csv, {d}/spoof_flows.csv")


if __name__ == "__main__":
    main()
