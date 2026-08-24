#!/usr/bin/env python3
# =============================================================================
# parse_logs.py ── OPC UA Anomaly log 解析 + 特徵工程（ML/NLP 管線的地基）
# =============================================================================
# 用途：把 attacks/logs/<場景>/anomaly.log 解析成結構化 DataFrame，抽 log 模板、
#       萃取單行 + 跨行（時序/session）特徵，並用同資料夾的 anomaly_marked.log
#       自動產生 ground-truth 標籤（label + attack_type），供後續監督/半監督評估。
#
# 設計重點（對應這批 log 的實際特性）：
#   1. 這批 log 高度結構化（就 ~7 種 level/category），不需重量級 parser；
#      這裡用輕量正規化把「變數」抽成佔位符，得到穩定的 template / template_id。
#      （之後若要換 Drain3，只需替換 extract_template() 一個函式。）
#   2. 4 種攻擊多為跨行語意/統計異常，所以特徵刻意包含：
#        - 每秒 sensor 事件計數（抓 S：同秒雙報）
#        - (內嵌時間戳, 數值) 是否重複（抓 RP：重放）
#        - session GUID 的 write-denied 計數（抓 T：對唯讀節點狂寫）
#        - 模板序列位置（給 DeepLog 之類序列模型當輸入）
#
# 輸出：
#   ml/out/parsed_all.csv        全部場景合併的結構化表（含特徵與標籤）
#   ml/out/templates.csv         模板字典（template_id -> template, 出現次數）
#   ml/out/summary.txt           統計摘要
#
# 執行：python3 ml/parse_logs.py
# =============================================================================
import os, re, glob, hashlib
from collections import defaultdict, Counter
import pandas as pd
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                      # Aggregation_clientServer/
LOGS = os.path.join(ROOT, "attacks", "logs")
OUT  = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

# ---- 1. 單行解析：拆出 timestamp / level / category / source / message ----
# 行格式（[Anomaly Input] 前綴後）：
#   [YYYY-MM-DD HH:MM:SS.mmm (UTC)] <level>/<cat>\t<message>
LINE_RE = re.compile(
    r"^\[(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \(UTC\)\]\s+"
    r"(?P<level>\w+)/(?P<cat>\w+)\s+(?P<msg>.*)$"
)

# ---- 1b. LogRecord 欄位後綴（新格式）----
# C 端現在會在每行尾端附加 OPC UA Part 22 LogRecord 欄位：
#   ... <message> | Severity=75 | SourceName=Sensor | EventType=application | SourceNode=ns=1;s=SensorSource
# 其中 SourceNode 由 aggregation_server 依 session 身分蓋章（client 無法自填）。
#
# 相容性：舊格式（無這些欄位）的 log 仍可解析，對應欄位為 None。
# 這讓既有的 24062 行資料與所有實驗結果保持有效，見 ml/EXPERIMENTS.md。
LR_FIELD_RE = re.compile(r"\s*\|\s*(?P<key>Severity|SourceName|EventType|SourceNode)=(?P<val>[^|]*)")

def split_logrecord_fields(msg):
    """從訊息尾端切出 LogRecord 欄位。回傳 (乾淨訊息, 欄位 dict)。

    重要：必須在做模板抽取『之前』切掉，否則 Severity/SourceNode 的值會被
    當成訊息內容的一部分，造成模板爆炸（每個不同 severity 都變成新模板）。

    SourceNode 取『最後一個』：伺服器的蓋章一律附加在最尾端，若攻擊者在自己
    的訊息內容裡偽造一個 SourceNode=，也會被伺服器的真值蓋過。
    """
    fields = {}
    first = None
    for m in LR_FIELD_RE.finditer(msg):
        if first is None:
            first = m.start()
        fields[m.group("key")] = m.group("val").strip()   # 後出現的覆蓋先出現的
    if first is None:
        return msg, {}
    return msg[:first].rstrip(), fields


def parse_line(raw):
    """raw 已去掉 '[Anomaly Input] ' 前綴。回傳 dict 或 None。"""
    m = LINE_RE.match(raw)
    if not m:
        return None
    d = m.groupdict()
    msg, lr = split_logrecord_fields(d["msg"])
    # source：優先用 LogRecord 的 SourceName（新格式），否則從訊息前綴推（舊格式）
    if lr.get("SourceName"):
        source = lr["SourceName"]
    elif msg.startswith("[System]"):
        source = "System"
    elif "[Sensor]" in msg:
        source = "Sensor"
    elif "[Motor]" in msg:
        source = "Motor"
    else:
        source = "App"
    # 抽出「距離數值」（若有），供 S/RP 特徵用
    dist = None
    dm = re.search(r"Updated distance: ([0-9.]+) cm", msg)
    if not dm:
        dm = re.search(r"Received distance: ([0-9.]+) cm", msg)
    if dm:
        dist = float(dm.group(1))
    # 抽 session GUID（若有），供 T 特徵用
    gm = re.search(r'Session "ns=1;g=([0-9a-f-]+)"', msg)
    guid = gm.group(1) if gm else None

    # ---- 馬達動作訊息的「距離 + 角度」（供物理一致性檢查用）----
    # 格式：[Motor] Distance too close (9.7); rotating motor to 0 degrees
    # 刻意不塞進上面的 `dist` 欄位：`dist` 是既有特徵（sensor_events_in_sec /
    # dist_ts_occurrence 都依賴它），改動它會連帶改變所有既有實驗結果。
    # 這裡另開欄位，純新增、不影響任何既有特徵。
    act_dist, act_angle = None, None
    am = re.search(r"Distance (?:too close|safe) \(([0-9.]+)\); rotating motor to (\d+) degrees", msg)
    if am:
        act_dist  = float(am.group(1))
        act_angle = int(am.group(2))

    # SourceNode：R(否認) 攻擊偵測的關鍵欄位。
    #   已驗證來源      → "ns=1;s=SensorSource" 等
    #   匿名/未授權寫入 → 伺服器蓋的是字串 "null"（偽造 log 的攻擊者落在這裡）
    #   舊格式          → 沒有這個欄位
    #
    # ⚠ 存進 CSV 前把 "null" 改寫成 "unverified"：pandas.read_csv 預設會把字串
    #   "null" 當成缺值 NaN，與「舊格式本來就沒有這個欄位」混為一談，導致下游
    #   分不出「匿名寫入」與「無此欄位」—— 那正好會抹掉本實驗要證明的訊號。
    src_node = lr.get("SourceNode")
    if src_node == "null":
        src_node = "unverified"
    src_verified = None if src_node is None else int(src_node != "unverified")

    sev = lr.get("Severity")
    return dict(ts=d["ts"], level=d["level"], cat=d["cat"],
                source=source, msg=msg, dist=dist, guid=guid,
                act_dist=act_dist, act_angle=act_angle,
                lr_Severity=int(sev) if sev and sev.isdigit() else None,
                lr_SourceName=lr.get("SourceName"),
                lr_EventType=lr.get("EventType"),
                lr_SourceNode=src_node,
                source_verified=src_verified)

# ---- 2. 模板抽取：把訊息裡的變數換成佔位符，得到穩定 template ----
# 針對這批 log 的變數種類做正規化。順序重要（先具體後一般）。
SUBS = [
    (re.compile(r'ns=1;g=[0-9a-f-]+'), 'ns=1;g=<GUID>'),
    (re.compile(r'opc\.tcp://[^\s"]+'), 'opc.tcp://<EP>'),
    (re.compile(r'opc\.udp://[^\s"]+'), 'opc.udp://<EP>'),
    (re.compile(r'\b\d+\.\d+\.\d+\.\d+\b'), '<IP>'),
    (re.compile(r'\bTCP \d+'), 'TCP <N>'),
    (re.compile(r'\bSC \d+'), 'SC <N>'),
    (re.compile(r'\bSubscription \d+'), 'Subscription <N>'),
    (re.compile(r'\bMonitoredItem \d+'), 'MonitoredItem <N>'),
    (re.compile(r'\bport \d+'), 'port <N>'),
    (re.compile(r'RequestId \d+'), 'RequestId <N>'),
    (re.compile(r'clienthandle \d+'), 'clienthandle <N>'),
    (re.compile(r'[-+]?\d+\.\d+'), '<F>'),   # 浮點（距離值、lifetime 等）
    (re.compile(r'\b\d+\b'), '<D>'),          # 其餘整數
]
def extract_template(msg):
    t = msg
    for rgx, rep in SUBS:
        t = rgx.sub(rep, t)
    return t

def template_id(t):
    return "T" + hashlib.md5(t.encode()).hexdigest()[:6]

# ---- 2b. OPC UA Part 22 LogRecord 欄位 ---------------------------------------
# OPC UA Part 22 (Diagnostics) Table 8 定義了標準 LogRecord 結構。
#
# 資料有兩種來源，本函式統一輸出成同一組 lr_* 欄位：
#   (a) 新格式 log —— C 端（sensor_pub/motor_sub）直接輸出 Severity/SourceName/
#       EventType，且 SourceNode 由 aggregation_server 依 session 身分蓋章。
#       這是「真的欄位」，其中 SourceNode 不可偽造。
#   (b) 舊格式 log —— 沒有這些欄位（本專案既有的 24062 行資料）。此時退回用
#       level/cat/source 推導 Severity 等值；SourceNode 只能是 None。
#
# 為什麼 SourceNode 一定要由伺服器蓋章、不能在解析層推導：
#   否認(R)攻擊會逐字複製真實 log 的格式（見 attacks/repudiation_attack.c）。
#   任何「從訊息內容推導出來的來源」都能被照抄。只有伺服器在收到寫入時
#   觀察到的 session 身分是攻擊者無法偽造的 —— 那才是可信的歸屬依據。
#   實測：攻擊者匿名注入的偽造 motor log 被蓋上 SourceNode=null，
#   真 sensor 則是 ns=1;s=SensorSource → R 從不可偵測變成可偵測。
#
# Table 9 - LogRecord Severity Mapping（Syslog 名稱 → severity 範圍）
#   Emergency 401-1000 / Alert 300-400 / Critical 251-300 / Error 201-250
#   Warning   151-200  / Notice 101-150 / Information 51-100 / Debug 1-50
SEVERITY_MAP = {
    "fatal": 500,   # Emergency   401-1000
    "error": 225,   # Error       201-250：有負面影響但不影響整體流程
    "warn":  175,   # Warning     151-200：應被注意但不需處理
    "info":   75,   # Information  51-100：一般資訊
    "debug":  25,   # Debug         1-50
    "trace":  25,
}

def severity_name(sev):
    """數值 severity → Table 9 的 Syslog 名稱。"""
    if sev is None:      return None
    if sev >= 401:       return "Emergency"
    if sev >= 300:       return "Alert"
    if sev >= 251:       return "Critical"
    if sev >= 201:       return "Error"
    if sev >= 151:       return "Warning"
    if sev >= 101:       return "Notice"
    if sev >= 51:        return "Information"
    return "Debug"

def to_log_record(p, tmpl_id):
    """輸出 Table 8 的 LogRecord 欄位。新格式用 log 自帶的值，舊格式則推導。"""
    # Severity：優先用 log 自帶的（新格式），否則由 level 推導（舊格式）
    sev = p.get("lr_Severity")
    if sev is None:
        sev = SEVERITY_MAP.get(p["level"], 75)
    return dict(
        lr_Time=p["ts"],
        lr_Severity=sev,
        lr_SeverityName=severity_name(sev),
        lr_SourceName=p.get("lr_SourceName") or p["source"],
        lr_EventType=p.get("lr_EventType") or p["cat"],
        # SourceNode：只有新格式才有值（伺服器蓋章）。舊格式為 None。
        lr_SourceNode=p.get("lr_SourceNode"),
        # 1=來源已驗證 / 0=匿名未驗證（攻擊者）/ None=舊格式無法判斷
        source_verified=p.get("source_verified"),
        lr_TemplateId=tmpl_id,
    )

# ---- 3. 讀 marked 檔，建立 (原始行文字 -> attack_type) 對照 ----
MARK_RE = re.compile(r'#\s*⚠\s*\[(?P<type>[A-Z]+)\]')
def load_labels(marked_path):
    """回傳 dict：原始行（去 '[Anomaly Input] ' 與行尾註解後）-> attack_type。"""
    labels = {}
    if not os.path.exists(marked_path):
        return labels
    for ln in open(marked_path, encoding="utf-8", errors="replace"):
        if not ln.startswith(">>>"):
            continue
        body = ln[3:].strip()
        mt = MARK_RE.search(body)
        atype = mt.group("type") if mt else "UNK"
        # 去掉行尾 '   # ⚠ ...' 註解，留下與 anomaly.log 相同的原始行
        core = re.split(r'\s+#\s*⚠', body)[0].strip()
        core = core.replace("[Anomaly Input] ", "", 1).strip()
        # marked 檔裡 GUID 行可能把 tab 顯示成 '\t'/空白，正規化空白後當 key
        labels[re.sub(r'\s+', ' ', core)] = atype
    return labels

def norm_key(raw):
    return re.sub(r'\s+', ' ', raw.replace("[Anomaly Input] ", "", 1)).strip()

# ---- 4. 主流程：逐場景解析 ----
def process_scenario(scendir):
    name = os.path.basename(scendir)
    anom = os.path.join(scendir, "anomaly.log")
    if not os.path.exists(anom):
        return None
    labels = load_labels(os.path.join(scendir, "anomaly_marked.log"))

    rows = []
    for raw in open(anom, encoding="utf-8", errors="replace"):
        raw = raw.rstrip("\n")
        if "[Anomaly Input]" not in raw:
            continue  # 只取被 Anomaly 收集到的行（跳過本地 client 狀態列）
        # 收集程序被中斷時，檔尾可能留下截斷的 '[Anomaly Input]'（無內容、無換行），
        # 此時 split 只會得到一段 → 直接跳過，不要讓整批解析炸掉。
        parts = raw.split("[Anomaly Input] ", 1)
        if len(parts) < 2:
            continue
        body = parts[1]
        p = parse_line(body)
        if p is None:
            continue
        # 採集中斷會留下「有表頭、訊息本體是空的」殘行。放行的話 extract_template
        # 會把空字串雜湊成一個假模板（Td41d8c），混進詞彙表污染所有序列模型
        # ——也會讓 embed_semantic 的 encode() 收到 NaN 而崩。
        if not p["msg"] or not p["msg"].strip():
            continue
        tmpl = extract_template(p["msg"])
        tid = template_id(tmpl)
        atype = labels.get(norm_key(raw), None)
        rows.append(dict(
            scenario=name, ts=p["ts"], level=p["level"], cat=p["cat"],
            source=p["source"], dist=p["dist"], guid=p["guid"],
            act_dist=p["act_dist"], act_angle=p["act_angle"],
            template=tmpl, template_id=tid,
            level_cat=f'{p["level"]}/{p["cat"]}',
            label=0 if atype is None else 1,
            attack_type=atype if atype else "normal",
            msg=p["msg"],
            # OPC UA Part 22 LogRecord 對映欄位（lr_ 前綴）
            **to_log_record(p, tid),
        ))
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    # 秒級時間戳（去毫秒），供「每秒 sensor 事件計數」
    df["ts_sec"] = df["ts"].str.slice(0, 19)
    return df

# ---- 5. 跨行特徵（在每個場景內計算，避免跨場景污染）----

# 拓樸無關的「角色」與「pair 歸屬」
# --------------------------------------------------------------------------
# ⚠ 為什麼需要這兩個欄位（2026-08-16 修）：
#   `source` 欄在新格式下就是 SourceName —— 單 pair 拓樸是 "Sensor"/"Motor"，
#   但 1:1 三 pair 拓樸是 "Sensor"/"Sensor2"/"Sensor3"/"Motor".../"Motor3"。
#   舊碼各處用 `source == "Sensor"` 精確比對來認「這是不是感測器行」，在三 pair
#   資料上**只認得 pair1**，Sensor2/Sensor3 共 15188 行被整批漏掉（實測
#   sensor_events_in_sec_persrc 對 Sensor2/3 全為 0）。
#   `role` 改從訊息前綴推（"[Sensor]"/"[Motor]"/"[System]"），與 SourceName 的
#   編號無關，因此拓樸再擴張也不必改判斷式。
#   `pair` 則是 1:1 配對的歸屬鍵：sensor_i 只該與 motor_i 做一致性比對，
#   跨 pair 比對會讓候選值集合變成 N 倍、「無回音」檢查因巧合命中而失效。
def _role_of(msg, source):
    m = msg if isinstance(msg, str) else ""
    if m.startswith("[Sensor]"):
        return "Sensor"
    if m.startswith("[Motor]"):
        return "Motor"
    if m.startswith("[System]"):
        return "System"
    s = source if isinstance(source, str) else ""
    if s.startswith("Sensor"):
        return "Sensor"
    if s.startswith("Motor"):
        return "Motor"
    if s == "System":
        return "System"
    return "App"

_PAIR_RE = re.compile(r"^(?:Sensor|Motor)(?:Source)?(\d*)$")

def _pair_of(source):
    """SourceName → pair 編號字串（"1"/"2"/…）；非設備行回 NaN。

    "Sensor" 與 "SensorSource" 都視為 pair1（無編號後綴＝第一組）。
    用 (\\d*)$ 而非取末字元，10 組以上的拓樸才不會把 "Sensor10" 讀成 pair0。
    """
    s = source if isinstance(source, str) else ""
    if ";s=" in s:
        s = s.split(";s=", 1)[1]
    m = _PAIR_RE.match(s.strip())
    if not m:
        return np.nan
    return m.group(1) or "1"


def add_cross_line_features(df):
    df = df.sort_values(["scenario", "ts"]).reset_index(drop=True)

    df["role"] = [_role_of(m, s) for m, s in zip(df["msg"], df["source"])]
    df["pair"] = [_pair_of(s) for s in df["source"]]
    # 分流鍵：優先用 server 蓋章的 SourceName，缺值時退回訊息推得的 source
    df["srckey"] = df["lr_SourceName"].where(df["lr_SourceName"].notna(), df["source"])

    # (a) S 特徵：同一秒內 [Sensor] Updated distance 的筆數（**全域**，跨所有 sensor）
    #   ⚠ 多 pair 拓樸下這一欄不可拿來當 spoof 判據：三 pair 時 benign 每秒本就有
    #     3 筆（各 sensor 一筆），`> 1` 對每一行都成立。請改用下面的 _persrc。
    #     保留本欄是為了單 sensor 舊資料的結果可重現。
    is_sensor_upd = df["msg"].str.contains("Updated distance", na=False) & (df["role"] == "Sensor")
    sec_counts = (df[is_sensor_upd].groupby(["scenario", "ts_sec"]).size()
                    .rename("sensor_events_in_sec"))
    df = df.merge(sec_counts, on=["scenario", "ts_sec"], how="left")
    df["sensor_events_in_sec"] = df["sensor_events_in_sec"].fillna(0).astype(int)

    # (a2) S 特徵（多 sensor 拓樸正解）：同一秒內、**同一個 SourceName** 的 sensor 筆數。
    #   正確的 spoof 判據是「**某一個** sensor 在同一秒送出 >1 筆」——即 per-SourceName。
    #   單 sensor 拓樸時 lr_SourceName 恆為 "Sensor"，本欄與 sensor_events_in_sec 等值，
    #   故對既有單 sensor 資料/結果零影響。
    persrc = (df[is_sensor_upd].groupby(["scenario", "ts_sec", "srckey"]).size()
                .rename("sensor_events_in_sec_persrc"))
    df = df.merge(persrc, on=["scenario", "ts_sec", "srckey"], how="left")
    df["sensor_events_in_sec_persrc"] = df["sensor_events_in_sec_persrc"].fillna(0).astype(int)

    # (a3) S 特徵（時序版）：同一 sensor 的**到達間隔**與**視窗速率**。
    #   為什麼加：實測 benign 的間隔極穩（median 1.002s、p1 0.990、p95 1.003），
    #   而 S 注入是**隨機相位**的 —— 被注入那一筆的 Δt 近似 U(0,1)（median 0.547）。
    #   因此逐行 Δt 門檻只抓得到「剛好插很近」的一半；而且注入會同時壓縮**下一筆
    #   真實讀數**的 Δt（實測 Δt<0.5 的 normal 行有 90.7% 前一行就是 S/RP），
    #   逐行看會製造假的 FP。不受相位影響的是**速率**：每個視窗的筆數。
    #   實測（10s 視窗、每 source）：benign 恆為 10，被注入的視窗 >=11
    #   → 規則 `sensor_win_count > 10` 達 P=0.923 R=0.908（視窗級）。
    SENSOR_WIN = "10s"
    t = pd.to_datetime(df["ts"], errors="coerce")

    # dt_source：**所有角色**的同來源到達間隔（秒）。
    #   給多變量序列模型（mvdeeplog.py）當輸入的一維 —— 模型從 benign 學到
    #   sensor 的節律是 1.002±0.005，S（隨機相位，median 0.547）與
    #   RP（重放帶原始內嵌時間戳，median 0.000）都會在這一維上偏離。
    #   ⚠ 與 sensor_dt 的差別：sensor_dt 只算 sensor 行（給規則層用），
    #     dt_source 對 motor/system 也算，因為模型的每一步都需要這個值。
    tm = t.notna()
    df["dt_source"] = np.nan
    df.loc[tm, "dt_source"] = (
        t[tm].groupby([df.loc[tm, "scenario"], df.loc[tm, "srckey"]])
             .diff().dt.total_seconds()
    )

    # sensor_dt：只在「sensor 讀數行」之間算間隔（跳過 "Connected to backend"
    #   之類的非讀數行）。與 dt_source 語意不同，刻意分開算，不要合併。
    df["sensor_dt"] = np.nan
    sm = is_sensor_upd & tm
    df.loc[sm, "sensor_dt"] = (
        t[sm].groupby([df.loc[sm, "scenario"], df.loc[sm, "srckey"]])
             .diff().dt.total_seconds()
    )

    df["_win"] = t.dt.floor(SENSOR_WIN)
    wc = (df[sm].groupby(["scenario", "srckey", "_win"]).size()
            .rename("sensor_win_count"))
    df = df.merge(wc, on=["scenario", "srckey", "_win"], how="left")
    df["sensor_win_count"] = df["sensor_win_count"].fillna(0).astype(int)
    df.drop(columns=["_win"], inplace=True)

    # (b) RP 特徵：同一場景內，(內嵌時間戳 ts, 距離值, 角色) 出現的次數；>1 = 疑似重放
    #   ⚠ 去重鍵必須包含 role（2026-08-16 修）：原本只用 (ts, dist)，而
    #     Sensor 的 "Updated distance: X" 與 Motor 的 "Received distance: X"
    #     是**同一筆讀數的正常回音**，兩行共用同一個內嵌時間戳與數值 → motor 行
    #     被算成 dtso=2，整批被誤判成重放。實測 topo3 測試集上這條規則產生
    #     1286 個誤報、precision 只有 0.126；加入 role 後誤報歸零、
    #     precision 1.000 而 RP recall 完全不變（94%）。
    #   RP 的定義本來就是「**同一個來源**重送同一份內容」，跨角色的重複不是重放。
    dup_key = (df["ts"].astype(str) + "|" + df["dist"].astype(str)
               + "|" + df["role"].astype(str))
    df["_dupkey"] = np.where(df["dist"].notna(), dup_key, np.nan)
    dup_counts = df[df["_dupkey"].notna()].groupby(["scenario", "_dupkey"]).cumcount() + 1
    df["dist_ts_occurrence"] = 0
    df.loc[dup_counts.index, "dist_ts_occurrence"] = dup_counts.values

    # (c) T 特徵：每個 session GUID 的 write-denied 累計次數
    is_denied = df["msg"].str.contains("BadUserAccessDenied", na=False)
    df["is_write_denied"] = is_denied.astype(int)
    df["session_denied_cumcount"] = 0
    for (scn, g), idx in df[is_denied & df["guid"].notna()].groupby(["scenario", "guid"]).groups.items():
        df.loc[idx, "session_denied_cumcount"] = range(1, len(idx) + 1)

    # (d) 序列特徵：場景內的模板序列位置（給 DeepLog 用）
    df["seq_pos"] = df.groupby("scenario").cumcount()

    # ========================================================================
    # (e) 數值特徵（不經模板化）——OT 場域的破綻常常就在數值裡
    # ========================================================================
    # 動機：模板化會把 "distance: 45.2 cm" 和 "38.7 cm" 壓成同一個模板，數值被丟掉。
    #   實測後果：DeepLog（純模板序列）對 RP 只有 50%，因為重放的破綻在參數值。
    #   以下特徵刻意「只看數值、不看文字」，與模板化互補。
    #   全部零訓練，門檻由物理量程與正常資料的分位數決定。

    # (e1) 值域：感測器的物理量程。超出 = 不可能的讀數（感測器故障或竄改）
    #      read_distance() 產生 2.0~50.0，故合法區間為 [2, 50]。
    DIST_MIN, DIST_MAX = 2.0, 50.0
    df["dist_out_of_range"] = (
        df["dist"].notna() & ((df["dist"] < DIST_MIN) | (df["dist"] > DIST_MAX))
    ).astype(int)

    # (e2) 變化率：相鄰兩筆 sensor 讀數的變化量 |Δ|。
    #      物理量有慣性，真實感測器不會瞬間大跳。
    #      ⚠ 本專案的 read_distance() 是 rand()，正常資料本身就劇烈跳動
    #        （實測 mean|Δ|=16.0、p99=43.1），因此這個特徵在**目前的模擬資料上
    #        不具鑑別力**。保留它是因為在真實感測器上這是最有效的一招；
    #        eval_numeric.py 會誠實報告它在本資料上的實際表現。
    #      ⚠ 必須以 srckey 分組：多 sensor 拓樸下若只用 scenario 分組，diff() 會把
    #        Sensor→Sensor2→Sensor3 三條互不相干的軌跡交錯相減，算出來的「變化率」
    #        是排程雜訊而非任何感測器的物理變化。
    df["dist_delta"] = np.nan
    sensor_mask = (df["role"] == "Sensor") & df["dist"].notna()
    df.loc[sensor_mask, "dist_delta"] = (
        df[sensor_mask].groupby(["scenario", "srckey"])["dist"].diff().abs()
    )

    # (e3) 感測器↔馬達 物理一致性（抓 S 欺騙的物理解法）
    #      正常時 motor 回報的距離，應該等於 sensor 先前送出的某一筆讀數。
    #      若攻擊者偽造 sensor 讀數，motor 收到的仍是真值 → 對不上。
    #
    #      ⚠ 關鍵：**不能用「同一秒」配對**。實測發現 motor 有約 1 秒的延遲
    #        （網路 + 訂閱通知），motor 在第 T 秒回報的是 sensor 第 T-1 秒的值。
    #        同秒配對會讓「正常行」全部被判為不一致（實測 FPR 85%）。
    #      正解：檢查 motor 的值是否出現在 sensor **最近 W 秒**的讀數集合中。
    #        對得上 → 一致（0）；對不上 → 該值不曾被 sensor 送出過（可疑）。
    #
    #      ⚠ 資料品質：2026-07-31 那批採集中，ST_20260731_003522 完全沒有 motor.log
    #        （motor 當時未正常運作，使用者已確認）。沒有 motor 端資料就無法做
    #        一致性檢查 —— 這類場景一律留 NaN（不判定），而不是當成「一致」，
    #        否則會把「沒資料」誤報成「沒問題」。
    #
    #      ⚠ 必須**逐 pair** 比對（2026-08-16 修）：1:1 三 pair 拓樸下 motor_i 只訂閱
    #        sensor_i。若把整個場景的 sensor/motor 混在一起比，候選值集合變成 3 倍，
    #        假讀數只要碰巧接近**其他 pair** 的真值就會被判為「一致」——
    #        一致性檢查會因此失效。groupby 的 pair 為 NaN 者（System/App 行）自動略過。
    MATCH_WINDOW = 5          # 容許的延遲秒數（>1s 的餘裕，涵蓋抖動）
    MIN_MOTOR_ROWS = 10       # motor 行數太少視為該 pair 無有效 motor 資料
    df["sensor_motor_mismatch"] = np.nan
    for (scn, pr), g in df.groupby(["scenario", "pair"]):
        s_rows = g[(g["role"] == "Sensor") & g["dist"].notna()]
        m_rows = g[(g["role"] == "Motor") & g["dist"].notna()]
        if s_rows.empty or len(m_rows) < MIN_MOTOR_ROWS:
            continue          # 無 motor 資料 → 該 pair 不做一致性判定
        # sensor 讀數：以 seq_pos 排序，供「最近 W 秒」查表
        s_times = pd.to_datetime(s_rows["ts_sec"]).astype("int64") // 10**9
        s_vals  = s_rows["dist"].values
        m_times = pd.to_datetime(m_rows["ts_sec"]).astype("int64") // 10**9
        for idx, mt, mv in zip(m_rows.index, m_times.values, m_rows["dist"].values):
            # 取 [mt-W, mt] 區間內的 sensor 讀數
            win = s_vals[(s_times.values >= mt - MATCH_WINDOW) & (s_times.values <= mt)]
            if len(win) == 0:
                continue                        # 無可比對的 sensor 讀數 → 不判定
            df.at[idx, "sensor_motor_mismatch"] = float(np.min(np.abs(win - mv)))

    #      反向檢查（**這才是抓 S 的方向**）：
    #        每一筆 sensor 讀數，motor 事後是否有回報同一個值？
    #        真讀數會被 motor 收到並回報；攻擊者直接把假 log 注入彙整伺服器，
    #        並沒有真的改動 sensor 節點 → motor 從未收到那個值 → 「無回音」。
    #        實測：S 攻擊的 15 筆假讀數，motor 回報同值次數全部為 0。
    #      這是物理因果檢查：真感測器的讀數必然在下游留下痕跡。
    #      （同樣逐 pair —— 跨 pair 的「回音」不算回音。）
    df["sensor_no_echo"] = np.nan
    for (scn, pr), g in df.groupby(["scenario", "pair"]):
        s_rows = g[(g["role"] == "Sensor") & g["dist"].notna()]
        m_rows = g[(g["role"] == "Motor") & g["dist"].notna()]
        if s_rows.empty or len(m_rows) < MIN_MOTOR_ROWS:
            continue
        s_times = pd.to_datetime(s_rows["ts_sec"]).astype("int64") // 10**9
        m_times = pd.to_datetime(m_rows["ts_sec"]).astype("int64") // 10**9
        m_vals  = m_rows["dist"].values
        for idx, st, sv in zip(s_rows.index, s_times.values, s_rows["dist"].values):
            # motor 應在 [st, st+W] 內回報這個值
            win = m_vals[(m_times.values >= st) & (m_times.values <= st + MATCH_WINDOW)]
            if len(win) == 0:
                continue                        # 視窗內沒有 motor 資料 → 不判定
            df.at[idx, "sensor_no_echo"] = int(np.min(np.abs(win - sv)) > 0.01)

    # (e4) 馬達動作 vs 距離的邏輯一致性（抓 R 偽造的動作 log）
    #      motor_sub.c 的規則：distance < SAFE_DISTANCE(20) → 轉 0 度，否則 90 度。
    #      偽造的動作 log 若違反這個規則，就是邏輯上不可能發生的動作。
    SAFE_DISTANCE = 20.0
    has_act = df["act_dist"].notna() & df["act_angle"].notna()
    expected_angle = np.where(df["act_dist"] < SAFE_DISTANCE, 0, 90)
    df["motor_logic_violation"] = 0
    df.loc[has_act, "motor_logic_violation"] = (
        df.loc[has_act, "act_angle"] != expected_angle[has_act.values]
    ).astype(int)

    df = df.drop(columns=["_dupkey"])
    return df

def main():
    scen_dirs = sorted([d for d in glob.glob(os.path.join(LOGS, "*")) if os.path.isdir(d)])
    all_df = []
    for sd in scen_dirs:
        d = process_scenario(sd)
        if d is not None and not d.empty:
            all_df.append(d)
    if not all_df:
        print("找不到可解析的 anomaly.log")
        return
    df = pd.concat(all_df, ignore_index=True)
    df = add_cross_line_features(df)

    # 模板字典
    tmpl_tab = (df.groupby(["template_id", "template"]).size()
                  .rename("count").reset_index().sort_values("count", ascending=False))

    df.to_csv(os.path.join(OUT, "parsed_all.csv"), index=False)
    tmpl_tab.to_csv(os.path.join(OUT, "templates.csv"), index=False)

    # 摘要
    lines = []
    lines.append(f"總行數（Anomaly 收集到的）: {len(df)}")
    lines.append(f"場景數: {df['scenario'].nunique()}  ->  {sorted(df['scenario'].unique())}")
    lines.append(f"不同模板數: {df['template_id'].nunique()}")
    lines.append(f"標記為異常的行: {int(df['label'].sum())}  (正常 {int((df['label']==0).sum())})")
    lines.append("\n各攻擊類別計數:")
    lines.append(df["attack_type"].value_counts().to_string())
    lines.append("\n特徵對攻擊的可分性（各攻擊類別下，關鍵特徵的代表值）:")
    for at in ["S", "T", "R", "RP"]:
        sub = df[df["attack_type"] == at]
        if sub.empty:
            continue
        lines.append(f"  [{at}] n={len(sub)}  "
                     f"sensor_events_in_sec(max)={sub['sensor_events_in_sec'].max()}  "
                     f"dist_ts_occurrence(max)={sub['dist_ts_occurrence'].max()}  "
                     f"session_denied_cumcount(max)={sub['session_denied_cumcount'].max()}")
    lines.append("\n模板 Top 10:")
    lines.append(tmpl_tab.head(10).to_string(index=False))

    # ---- OPC UA Part 22 LogRecord 對映狀態 ----
    lines.append("\n" + "=" * 68)
    lines.append("OPC UA Part 22 (Diagnostics) Table 8 - LogRecord 欄位對映狀態")
    lines.append("=" * 68)
    lines.append(f"{'LogRecord 欄位':<14} {'Optional':<9} {'本專案來源':<14} 狀態")
    lines.append("-" * 68)
    n_new = int(df["lr_SourceNode"].notna().sum())      # 新格式（C 端已輸出欄位）
    n_old = len(df) - n_new
    src_state = ("✓ 伺服器端蓋章（不可偽造）" if n_new else "✗ 缺（R 無法偵測的根因）")
    field_status = [
        ("Time",         "False", "ts",            "✓ 已對映"),
        ("Severity",     "False", "level",         "✓ 已對映（Table 9 數值化）"),
        ("Message",      "False", "msg",           "✓ 已對映"),
        ("EventType",    "True",  "cat",           "△ 以 category 近似"),
        ("SourceName",   "True",  "source",        "✓ 已對映"),
        ("SourceNode",   "True",  "session 身分",   src_state),
        ("TraceContext", "True",  "—",             "✗ 缺（無跨 server 關聯）"),
        ("AdditionalData", "True", "—",            "✗ 缺"),
    ]
    for f, opt, src, st in field_status:
        lines.append(f"{f:<14} {opt:<9} {src:<14} {st}")
    lines.append("-" * 68)
    lines.append(f"格式分布：新格式（含 LogRecord 欄位）{n_new} 行 / 舊格式 {n_old} 行")
    lines.append("")
    lines.append("Severity 分布（Table 9）:")
    for sev, cnt in sorted(df["lr_Severity"].value_counts().items(), reverse=True):
        lines.append(f"  {int(sev):>4} ({severity_name(sev) or '?':<11}) : {cnt:>6} 行")

    # ---- SourceNode 來源歸屬（R 偵測的關鍵）----
    if n_new:
        lines.append("")
        lines.append("SourceNode 來源歸屬統計（僅新格式）:")
        for node, cnt in df["lr_SourceNode"].value_counts().items():
            tag = "未驗證（匿名寫入）" if node == "unverified" else "已驗證"
            lines.append(f"  {str(node):<28} {cnt:>6} 行   {tag}")
        # 這一欄能不能分出 R，直接在這裡量化
        sub = df[df["source_verified"].notna()]
        if len(sub):
            unver = sub[sub["source_verified"] == 0]
            atk = int((unver["label"] == 1).sum()) if "label" in unver else 0
            lines.append("")
            lines.append(f"  未驗證來源共 {len(unver)} 行，其中標記為攻擊的有 {atk} 行")
            if len(unver):
                lines.append(f"  → 以『SourceNode==null』當偵測規則：precision = {atk}/{len(unver)}"
                             f" = {atk/len(unver):.1%}")
    lines.append("")
    if n_new:
        lines.append("關鍵：SourceNode 現由 aggregation_server 依 session 身分蓋章，寫入者無法自填。")
        lines.append("攻擊者能逐字複製 log 內容，卻無法冒用 session 身分 → 偽造的 log 一律被標成")
        lines.append("SourceNode=null，與真來源（ns=1;s=SensorSource / MotorSource）明確可分。")
        lines.append("→ 這使 R(否認) 從『任何 ML 模型都測不到』變成『一條規則就能測到』，")
        lines.append("  印證了 ml/EXPERIMENTS.md 的結論：R 的正解是工程手段，不是模型手段。")
    else:
        lines.append("關鍵觀察：SourceNode 是 Table 8 已定義的『這筆記錄來自哪個 Node』欄位，")
        lines.append("但這批資料為舊格式、並未填寫 → log 無法歸屬來源身分 → R(否認)")
        lines.append("攻擊在原理上就無法從 log 偵測。這不是規範的缺口，是實作沒有填。")
        lines.append("→ C 端已修正（見 aggregation_server.c），重新採集即可獲得此欄位。")
    summary = "\n".join(lines)
    open(os.path.join(OUT, "summary.txt"), "w", encoding="utf-8").write(summary + "\n")
    print(summary)
    print(f"\n輸出:\n  {OUT}/parsed_all.csv\n  {OUT}/templates.csv\n  {OUT}/summary.txt")

if __name__ == "__main__":
    main()
