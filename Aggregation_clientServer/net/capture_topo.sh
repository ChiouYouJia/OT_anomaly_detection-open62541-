#!/bin/bash
# =============================================================================
# capture_topo.sh ── 1 sensor + N motor 拓撲：同時採集 log 與 pcap（GNN 用）
# =============================================================================
# 與 capture_attacks.sh 的差異：
#   1. 啟動 **N 台 motor**（各自帶 id → 不同 sessionName → 不同 SourceNode）。
#      這是 GNN 的前提：三台 motor 必須是三個**可區分**的節點，否則會塌縮成一個。
#   2. 同時保留 **log**（應用層，含 SourceNode）與 **pcap**（網路層，含連線結構），
#      兩者時間對齊 → 可建「節點=主機、邊=連線」的圖，節點特徵來自 log、
#      邊特徵來自流量。
#   3. 每個攻擊場景**獨立一份 pcap**，避免混在一起無法歸因。
#
# 拓撲：
#        sensor_pub(server@4842)
#          ▲        ▲        ▲            ← 3 台 motor 訂閱同一個 sensor
#       motor1   motor2   motor3
#          │        │        │
#          └────────┼────────┘  各自把 log 寫進 ▼
#                   ▼
#        aggregation_server(server@4840) ← Anomaly_client 讀取
#                   ▲
#              attacker（匿名，攻擊時才出現）
#
# 用法：
#   ./net/capture_topo.sh                 # 預設 benign 300s + 四攻擊各 300s，3 motor
#   ./net/capture_topo.sh 600 300 3       # benign秒 攻擊秒 motor數
#   ./net/capture_topo.sh 120 120 3 quick # 快速驗證流程
# =============================================================================
set -u

BENIGN_SEC="${1:-300}"
ATTACK_SEC="${2:-300}"
N_MOTOR="${3:-3}"
MODE="${4:-full}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

# 伺服器端合法身分上限（見 aggregation_server.c resolve_source_node）。
# 沒設的話預設 3 —— 一旦 N_MOTOR>3 就會有 motor 拿不到具名 SourceNode。
export AGG_N_MOTOR="$N_MOTOR"

STAMP="$(date +%Y%m%d_%H%M%S)"
CAPROOT="$ROOT/net/captures/topo_${N_MOTOR}motor_${STAMP}"
mkdir -p "$CAPROOT"
REPORT="$CAPROOT/report.txt"

IFACE="lo"
# 同時抓兩個 OPC UA server：4840(aggregation) + 4842(sensor)。
BPF="tcp port 4840 or tcp port 4842"

log() { echo "$@" | tee -a "$REPORT"; }

# ---------------------------------------------------------------------------
# 0) 抓包工具與權限
# ---------------------------------------------------------------------------
probe() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1 || return 1
  if [ "$tool" = "tcpdump" ]; then
    timeout 3 tcpdump -i "$IFACE" -c 1 -w /dev/null >/dev/null 2>&1 & local pp=$!
    sleep 1; kill -9 $pp 2>/dev/null
    timeout 3 tcpdump -i "$IFACE" -c 1 -w /dev/null >/dev/null 2>&1
    [ $? -le 1 ]
  else
    return 1
  fi
}

CAP_CMD=""
if probe tcpdump; then CAP_CMD="tcpdump"
elif command -v dumpcap >/dev/null 2>&1; then CAP_CMD="dumpcap"
else
  echo "✗ 找不到可用的抓包工具（tcpdump/dumpcap），或無 lo 抓包權限。"
  echo "  一次性授權： sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump"
  exit 1
fi

# ---------------------------------------------------------------------------
# 1) 編譯
# ---------------------------------------------------------------------------
echo "[topo] 編譯..."
for p in aggregation_server sensor_pub Anomaly_client; do
  if [ ! -x "$p" ] || [ "$p.c" -nt "$p" ]; then
    gcc -o "$p" "$p.c" $UA_INC $UA_LIB 2>/tmp/topo_$p.err \
      && echo "[topo]   ✓ $p" || { echo "[topo] ✗ $p"; sed -n '1,5p' /tmp/topo_$p.err; exit 1; }
  fi
done

HAVE_MOTOR=1
if [ ! -x motor_sub ] || [ motor_sub.c -nt motor_sub ]; then
  gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/dev/null \
    && echo "[topo]   ✓ motor_sub" || { HAVE_MOTOR=0; echo "[topo] ⚠ motor_sub 無法編譯"; }
fi
[ "$HAVE_MOTOR" = "0" ] && { echo "[topo] ✗ 本實驗需要 motor（拓撲的一半），中止。"; exit 1; }

# 驗證多實例支援（避免用到舊版二進位 → 三台 motor 同名，塌縮成同一個圖節點）
if ! grep -q "MotorSource%d" motor_sub.c; then
  echo "[topo] ✗ motor_sub.c 不含多實例身分邏輯，請確認已套用改造。"; exit 1
fi
# 2a 之後 SOURCE_REGISTRY 改成動態（依 AGG_N_MOTOR 界定的封閉世界），
# 執行檔裡不再有 "MotorSource2" 這個字串，改檢查原始碼有無動態身分邏輯。
if ! grep -q "AGG_N_MOTOR" aggregation_server.c; then
  echo "[topo] ✗ aggregation_server.c 仍是寫死的 SOURCE_REGISTRY → 第 4 台以後的 motor 會被判成 null。"
  exit 1
fi
echo "[topo] ✓ 已確認多實例身分與 SourceNode 登記"

# 來源 IP 綁定的 shim：讓每台 motor 在 pcap 上有穩定且不同的來源位址
if [ ! -f net/bindsrc.so ] || [ net/bindsrc.c -nt net/bindsrc.so ]; then
  gcc -shared -fPIC -o net/bindsrc.so net/bindsrc.c -ldl 2>/dev/null \
    && echo "[topo]   ✓ bindsrc.so" \
    || { echo "[topo] ✗ bindsrc.so 編譯失敗"; exit 1; }
fi

if [ "$MODE" = "quick" ]; then N_INJ=6; else N_INJ=10; fi
[ "$ATTACK_SEC" -ge 240 ] && N_INJ=12
for a in spoof_attack repudiation_attack tamper_attack replay_attack \
         stealth_spoof_attack compromised_node_attack; do
  gcc -o "attacks/$a" -DBASELINE_SEC=$ATTACK_SEC "attacks/$a.c" $UA_INC $UA_LIB 2>/dev/null \
    && echo "[topo]   ✓ $a" || { echo "[topo] ✗ $a"; exit 1; }
done

kill_all() {
  ps aux | grep -E 'aggregation_server|sensor_pub|motor_sub|Anomaly_client|_attack' \
    | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 1
}
PIDS=(); CAP_PID=""
cleanup_trap() {
  echo ""; echo "[topo] 中斷，收尾中..."
  [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2>/dev/null
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  kill_all; exit 130
}
trap cleanup_trap INT TERM

# ---------------------------------------------------------------------------
# 2) 系統啟停（N 台 motor）
# ---------------------------------------------------------------------------
start_system() {
  local dest="$1"; PIDS=()
  ./aggregation_server > "$dest/agg.log"    2>&1 & PIDS+=($!)
  sleep 2
  ./sensor_pub         > "$dest/sensor.log" 2>&1 & PIDS+=($!)
  sleep 1
  # 每台 motor 綁不同的 loopback 來源 IP（127.0.0.(i+1)），讓 pcap 能穩定分辨
  # 是哪一台。詳見 net/bindsrc.c 的說明（不需要 root，也不需要虛擬機）。
  for i in $(seq 1 "$N_MOTOR"); do
    BIND_SRC="127.0.0.$((i+1))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
      ./motor_sub "$i" > "$dest/motor${i}.log" 2>&1 & PIDS+=($!)
  done
  ./Anomaly_client     > "$dest/anomaly.log" 2>&1 & PIDS+=($!)
  sleep 3
}
stop_system() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; sleep 1; kill_all; }

start_capture() {
  if [ "$CAP_CMD" = "tcpdump" ]; then
    tcpdump -i "$IFACE" -n -s 0 -w "$1" "$BPF" >/dev/null 2>&1 &
  else
    dumpcap -i "$IFACE" -f "$BPF" -w "$1" >/dev/null 2>&1 &
  fi
  CAP_PID=$!; sleep 1
}
stop_capture() { [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; CAP_PID=""; sleep 1; }

# SourceNode 分布報告（驗證三台 motor 真的可區分）
report_scenario() {
  local dest="$1" name="$2"
  {
    echo "--- $name"
    echo "    pcap: $(stat -c%s "$dest"/*.pcap 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0) bytes"
    echo "    SourceNode 分布："
    grep -o 'SourceNode=[^ ]*' "$dest/anomaly.log" 2>/dev/null | sort | uniq -c | sed 's/^/      /'
  } | tee -a "$REPORT"
}

{
  echo "============================================================"
  echo "1 sensor + ${N_MOTOR} motor 拓撲流量採集  ($STAMP)"
  echo "============================================================"
  echo "介面=$IFACE  BPF='$BPF'  工具=$CAP_CMD"
  echo "benign=${BENIGN_SEC}s  攻擊各=${ATTACK_SEC}s"
  echo ""
} | tee "$REPORT"

kill_all

# ---------------------------------------------------------------------------
# 3) benign（純正常）
# ---------------------------------------------------------------------------
DEST="$CAPROOT/benign"; mkdir -p "$DEST"
log "=== (1) 純正常 benign：${BENIGN_SEC}s ==="
log "    ⚠️ 這段請勿執行任何攻擊程式"
start_system "$DEST"
start_capture "$DEST/benign.pcap"
sleep "$BENIGN_SEC"
stop_capture; stop_system
report_scenario "$DEST" "benign"
log ""

# ---------------------------------------------------------------------------
# 4) 四種攻擊，各自獨立 pcap
# ---------------------------------------------------------------------------
declare -A ATK_BIN=( [S]=spoof_attack [R]=repudiation_attack [T]=tamper_attack [RP]=replay_attack )
i=2
for k in S T R RP; do
  DEST="$CAPROOT/$k"; mkdir -p "$DEST"
  log "=== ($i) 攻擊 $k：${ATK_BIN[$k]}（${ATTACK_SEC}s）==="
  start_system "$DEST"
  start_capture "$DEST/$k.pcap"
  "./attacks/${ATK_BIN[$k]}" > "$DEST/${ATK_BIN[$k]}.log" 2>&1 & ATK=$!
  sleep $(( ATTACK_SEC + 10 ))
  kill -9 $ATK 2>/dev/null
  stop_capture; stop_system
  report_scenario "$DEST" "$k"
  log ""
  i=$(( i + 1 ))
done

# ---------------------------------------------------------------------------
# 5) 四攻擊並存（最真實）
# ---------------------------------------------------------------------------
DEST="$CAPROOT/all"; mkdir -p "$DEST"
log "=== ($i) 四攻擊並存 ==="
start_system "$DEST"
start_capture "$DEST/all.pcap"
for k in S T R RP; do
  "./attacks/${ATK_BIN[$k]}" > "$DEST/${ATK_BIN[$k]}.log" 2>&1 & PIDS+=($!)
done
sleep $(( ATTACK_SEC + 10 ))
stop_capture; stop_system
report_scenario "$DEST" "all"
log ""
i=$(( i + 1 ))

# ---------------------------------------------------------------------------
# 6) 進階攻擊 A：stealth_spoof —— 每秒都寫，消除「只在少數秒出現」的流量指紋
#    攻擊者綁一個不屬於任何 motor 的來源 IP（127.0.0.<N_MOTOR+2>）。
# ---------------------------------------------------------------------------
ATK_IP="127.0.0.$(( N_MOTOR + 2 ))"
DEST="$CAPROOT/stealth"; mkdir -p "$DEST"
log "=== ($i) 進階攻擊 stealth_spoof（每秒寫、來源 $ATK_IP）==="
start_system "$DEST"
start_capture "$DEST/stealth.pcap"
BIND_SRC="$ATK_IP" LD_PRELOAD="$ROOT/net/bindsrc.so" \
  ./attacks/stealth_spoof_attack > "$DEST/stealth_spoof_attack.log" 2>&1 & ATK=$!
sleep $(( ATTACK_SEC + 10 ))
kill -9 $ATK 2>/dev/null
stop_capture; stop_system
report_scenario "$DEST" "stealth"
log ""
i=$(( i + 1 ))

# ---------------------------------------------------------------------------
# 7) 進階攻擊 B：compromised_node —— 冒用合法 session 身分（憑證被竊）
#    只啟動 N_MOTOR-1 台真 motor，空出一個合法身分給攻擊者冒用，避免同名衝突。
#    攻擊者連線結構完全正常（就是一台 motor），SourceNode 也是合法的 →
#    SourceNode==null 規則與流量指紋雙雙失效，破綻只剩「回報值與 sensor 不符」。
# ---------------------------------------------------------------------------
DEST="$CAPROOT/compromised"; mkdir -p "$DEST"
IMPERSONATE="MotorSource${N_MOTOR}"          # 冒用最後一台的身分
log "=== ($i) 進階攻擊 compromised_node（冒用 $IMPERSONATE）==="
# 手動啟動系統，但少開一台真 motor（空出 $IMPERSONATE 這個身分）
PIDS=()
./aggregation_server > "$DEST/agg.log" 2>&1 & PIDS+=($!); sleep 2
./sensor_pub         > "$DEST/sensor.log" 2>&1 & PIDS+=($!); sleep 1
for j in $(seq 1 $(( N_MOTOR - 1 ))); do
  BIND_SRC="127.0.0.$((j+1))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
    ./motor_sub "$j" > "$DEST/motor${j}.log" 2>&1 & PIDS+=($!)
done
./Anomaly_client     > "$DEST/anomaly.log" 2>&1 & PIDS+=($!); sleep 3
start_capture "$DEST/compromised.pcap"
# 攻擊者用被空出的身分連線，綁該身分對應的 IP（假裝就是那台 motor）
BIND_SRC="127.0.0.$(( N_MOTOR + 1 ))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
  ./attacks/compromised_node_attack "$IMPERSONATE" \
    > "$DEST/compromised_node_attack.log" 2>&1 & ATK=$!
sleep $(( ATTACK_SEC + 10 ))
kill -9 $ATK 2>/dev/null
stop_capture; stop_system
report_scenario "$DEST" "compromised"

{
  echo ""
  echo "============================================================"
  echo "採集完成 → $CAPROOT"
  echo "============================================================"
  echo "下一步："
  echo "  ml/venv/bin/python net/build_graph.py $CAPROOT"
} | tee -a "$REPORT"
echo "[topo] 報告：$REPORT"
