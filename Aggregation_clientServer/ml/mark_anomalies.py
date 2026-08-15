#!/usr/bin/env python3
# =============================================================================
# mark_anomalies.py ── 由 anomaly.log 產生 anomaly_marked.log（ground-truth 標籤）
# =============================================================================
# 這是 collect_v2.sh 內 make_marked() 的獨立可重跑版本，**同一套標準**。
# parse_logs.py 是讀 anomaly_marked.log 取標籤的，不是自己生標籤；因此任何採集
# 腳本都必須在採集後產生 marked 檔。collect_topo3.sh 早期版本漏了這步，用本腳本補標。
#
# 標準（與 collect_v2.sh 逐字一致）：
#   SourceNode=null            → 依內容分類 S / R / RP（RP=該內容先前已出現過）
#   BadUserAccessDenied        → T
#   其餘                       → 正常
#
# 用法：
#   ml/venv/bin/python ml/mark_anomalies.py <場景資料夾> [<場景資料夾> ...]
#   ml/venv/bin/python ml/mark_anomalies.py attacks/logs/topo3_*_20260811_232548
# =============================================================================
import sys, os, re

DESC = {"R": "Repudiation 否認：冒充他人(motor)寫入、事後無法歸屬的偽造操作 log",
        "S": "Spoofing 欺騙：偽造的 sensor 距離（同一秒出現雙報）",
        "T": "Tampering 竄改：對唯讀節點寫入，被拒 BadUserAccessDenied",
        "RP": "Replay 重放：內容(含原始時間戳)與過去事件完全相同、被重送的重複行"}


def classify(msg, seen_before):
    if "BadUserAccessDenied" in msg:
        return "T"
    if "[Motor]" in msg and ("rotating motor" in msg or "Distance too close" in msg
                             or "Distance safe" in msg):
        return "R"
    if "[Sensor]" in msg and "Updated distance" in msg:
        return "RP" if seen_before else "S"
    return None


def core(s):
    s = s.replace("[Anomaly Input] ", "", 1)
    s = re.split(r'\s*\|\s*SourceNode=', s)[0]
    return re.sub(r'\s+', ' ', s).strip()


def mark(dest):
    scen = os.path.basename(dest.rstrip("/"))
    anom = os.path.join(dest, "anomaly.log")
    if not os.path.exists(anom):
        print(f"  [skip] {scen}: 無 anomaly.log")
        return
    lines = open(anom, encoding="utf-8", errors="replace").read().splitlines()

    out, n_marked, seen = [], {}, set()
    for raw in lines:
        if "[Anomaly Input]" in raw:
            body = core(raw)
            at = None
            if "SourceNode=null" in raw:
                at = classify(body, body in seen) or "R"
            elif "BadUserAccessDenied" in raw:
                at = "T"
            if at:
                n_marked[at] = n_marked.get(at, 0) + 1
                out.append(f">>> {raw}   # ⚠ [{at}] {DESC[at]}")
                seen.add(body); continue
            seen.add(body)
        out.append(raw)

    hdr = ["# " + "=" * 76,
           f"# anomaly.log 異常標記版  —  場景：{scen}",
           "# 行首 '>>>' = 異常。行尾 '# ⚠ [類別] 說明'。"]
    for a in ["S", "T", "R", "RP"]:
        if a in n_marked:
            hdr.append(f"#   [{a}] = {DESC[a]}")
    hdr += ["# grep： grep '^>>>' anomaly_marked.log ；grep '\\[R\\]'",
            "# " + "=" * 76, ""]

    with open(os.path.join(dest, "anomaly_marked.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(hdr + out) + "\n")
    print(f"  {scen}: " + (", ".join(f"{k}={v}" for k, v in sorted(n_marked.items())) or "無異常"))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("用法: mark_anomalies.py <場景資料夾> [...]")
    for d in sys.argv[1:]:
        if os.path.isdir(d):
            mark(d)
