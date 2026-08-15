#!/bin/bash
# =============================================================================
# capture_spoof.sh ── 打 Spoofing 攻擊 + 抓取網路流量（供 ML 異常檢測）
# =============================================================================
# 這條管線與 ml/ 的「log 為本」管線互補：ml/ 解析『應用層 log 文字』，
# 本管線改抓『網路封包(pcap)』，用封包/流量統計特徵做異常檢測。
#
# 流程：
#   1) 啟動真實系統（aggregation_server + sensor_pub [+ motor_sub] + Anomaly_client）
#   2) 用 tcpdump 抓 loopback(lo) 上、port 4840 的 OPC UA 流量
#   3) 先跑一段純正常 baseline（benign.pcap，訓練用）
#   4) 再跑一段「同樣系統 + spoof_attack 匿名注入」（spoof.pcap，測試用）
#   spoof_attack 冒充 sensor 匿名連上 4840 寫入偽造 log → 在網路上多出一條
#   額外 TCP 連線 / 額外 Write 請求，這正是流量統計特徵要抓的破綻。
#
# 權限：抓 loopback 需要 CAP_NET_RAW。本機的 dumpcap 需 wireshark 群組、
#   tcpdump 預設無 cap。請先做一次性授權（擇一，見 README）：
#     sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
#   之後 tcpdump 免 sudo 即可抓 lo。本腳本會先檢查權限，缺就直接指示你怎麼開。
#
# 用法：
#   ./net/capture_spoof.sh              # 預設 benign 120s + spoof 120s
#   ./net/capture_spoof.sh 300 300      # benign 300s + spoof 300s
#   ./net/capture_spoof.sh 60 60 quick  # quick：spoof 潛伏期縮短成與抓取同長
#
# ⚠️ 僅用於你自己機器上、你自己系統的授權安全測試。
# =============================================================================
set -u

BENIGN_SEC="${1:-120}"
SPOOF_SEC="${2:-120}"
MODE="${3:-full}"                       # full | quick

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

IFACE="lo"
PORT=4840
BPF="tcp port $PORT"                    # 只抓 OPC UA server 的流量

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
CAPROOT="$HERE/captures"
DEST="$CAPROOT/spoof_${STAMP}"
mkdir -p "$DEST"
REPORT="$DEST/capture_report.txt"

log() { echo "[cap] $*"; }

# ---------------------------------------------------------------------------
# 0) 權限檢查：確認可以在 lo 上抓包（不需 sudo 就能跑完整條管線）
# ---------------------------------------------------------------------------
CAP_CMD=""
# 探測是否能在 lo 上抓包。用 -c 1（抓 1 個封包就結束；-c 0 是無效值），
# 並在背景戳一下 loopback 製造流量，避免沒封包而卡到 timeout 被誤判成無權限。
probe() {           # $1 = 工具名(tcpdump|dumpcap)
  local tool="$1" tmp; tmp="$(mktemp)"
  if [ "$tool" = "tcpdump" ]; then
    timeout 3 tcpdump -i "$IFACE" -c 1 -w /dev/null >/dev/null 2>&1 & local pp=$!
  else
    timeout 3 dumpcap -i "$IFACE" -c 1 -w /dev/null >/dev/null 2>&1 & local pp=$!
  fi
  sleep 0.3
  ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1     # 製造一個 loopback 封包給探測抓
  wait "$pp" 2>/dev/null; local rc=$?
  rm -f "$tmp"
  return $rc         # 0 = 有權限抓到；非 0 = 無權限或抓不到
}
if probe tcpdump; then
  CAP_CMD="tcpdump"
elif command -v dumpcap >/dev/null 2>&1 && probe dumpcap; then
  CAP_CMD="dumpcap"
else
  cat <<EOF
[cap] ✗ 目前無權限在 $IFACE 上抓包。請先做一次性授權（擇一）：

  (建議) 給 tcpdump capability，之後免 sudo：
      sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

  或 加入 wireshark 群組（需登出再登入才生效）：
      sudo usermod -aG wireshark $USER

  或 每次用 sudo 跑本腳本：
      sudo -E ./net/capture_spoof.sh $BENIGN_SEC $SPOOF_SEC $MODE

授權完成後重跑本腳本即可。
EOF
  exit 2
fi
log "抓包工具：$CAP_CMD（$IFACE, '$BPF'）"

# ---------------------------------------------------------------------------
# 1) 建置：主系統 + spoof 攻擊程式
# ---------------------------------------------------------------------------
log "=== 建置檢查 ==="
need_build=0
for pair in "aggregation_server aggregation_server.c" "sensor_pub sensor_pub.c" "Anomaly_client Anomaly_client.c"; do
  set -- $pair
  { [ ! -x "$1" ] || [ "$2" -nt "$1" ]; } && need_build=1
done
if [ "$need_build" = "1" ]; then
  for p in aggregation_server sensor_pub Anomaly_client; do
    gcc -o "$p" "$p.c" $UA_INC $UA_LIB 2>/tmp/cap_build_$p.err \
      && log "  ✓ $p" || { log "  ✗ $p 編譯失敗"; sed -n '1,5p' /tmp/cap_build_$p.err; exit 1; }
  done
fi

HAVE_MOTOR=1
if [ ! -x motor_sub ] || [ motor_sub.c -nt motor_sub ]; then
  gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/dev/null \
    && log "  ✓ motor_sub" || { HAVE_MOTOR=0; log "  ⚠ motor_sub 缺 lgpio → 本次不啟動 motor"; }
fi

# spoof 潛伏期必須與抓取窗一致，否則注入會落在抓取窗外（攻擊原始碼預設潛伏
# 300s，若只抓 120s 就在第一筆注入前被殺 → 一筆都沒注入、標籤全 0）。
# 因此無論哪種模式，都把 BASELINE_SEC 綁成 SPOOF_SEC；注入筆數依時長給，
# 確保注入稀疏但確實落在抓取期間內。
N_INJ=8
[ "$SPOOF_SEC" -ge 240 ] && N_INJ=12
SPOOF_BUILD_FLAG="-DBASELINE_SEC=$SPOOF_SEC -DN_INJECT=$N_INJ"
gcc -o attacks/spoof_attack $SPOOF_BUILD_FLAG attacks/spoof_attack.c $UA_INC $UA_LIB 2>/tmp/cap_build_spoof.err \
  && log "  ✓ spoof_attack ($SPOOF_BUILD_FLAG)" \
  || { log "  ✗ spoof_attack 編譯失敗"; sed -n '1,5p' /tmp/cap_build_spoof.err; exit 1; }

# ---------------------------------------------------------------------------
# 進程管理
# ---------------------------------------------------------------------------
kill_all() {
  ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client|spoof_attack' | grep -v grep \
    | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 1
}
PIDS=(); CAP_PID=""
cleanup_trap() {
  echo ""; log "中斷，收尾中..."
  [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2>/dev/null
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  kill_all; exit 130
}
trap cleanup_trap INT TERM

start_system() {
  local dest="$1"
  PIDS=()
  ./aggregation_server > "$dest/agg.log"     2>&1 & PIDS+=($!)
  sleep 2
  ./sensor_pub         > "$dest/sensor.log"  2>&1 & PIDS+=($!)
  [ "$HAVE_MOTOR" = "1" ] && { ./motor_sub > "$dest/motor.log" 2>&1 & PIDS+=($!); }
  ./Anomaly_client     > "$dest/anomaly.log" 2>&1 & PIDS+=($!)
  sleep 3
}
stop_system() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  sleep 1; kill_all
}

start_capture() {  # $1 = pcap 路徑
  if [ "$CAP_CMD" = "tcpdump" ]; then
    tcpdump -i "$IFACE" -n -s 0 -w "$1" "$BPF" >/dev/null 2>&1 &
  else
    dumpcap -i "$IFACE" -f "$BPF" -w "$1" >/dev/null 2>&1 &
  fi
  CAP_PID=$!
  sleep 1                                # 讓抓取器就緒
}
stop_capture() {
  [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2>/dev/null
  wait "$CAP_PID" 2>/dev/null
  CAP_PID=""
  sleep 1
}

{
  echo "============================================================"
  echo "Spoofing 攻擊 + 網路流量抓取報告  ($STAMP)"
  echo "============================================================"
  echo "介面=$IFACE  BPF='$BPF'  工具=$CAP_CMD"
  [ "$HAVE_MOTOR" = "0" ] && echo "註：本機無 GPIO，motor_sub 未啟動。"
  echo ""
} | tee "$REPORT"

kill_all

# ---------------------------------------------------------------------------
# 2) benign.pcap —— 純正常流量（訓練用）
# ---------------------------------------------------------------------------
log "=== (1/2) 純正常 baseline：抓 ${BENIGN_SEC}s → benign.pcap ==="
log "    ⚠️ 這段請勿執行任何攻擊程式"
start_system "$DEST"
start_capture "$DEST/benign.pcap"
sleep "$BENIGN_SEC"
stop_capture
stop_system
sz=$(stat -c%s "$DEST/benign.pcap" 2>/dev/null || echo 0)
echo "    benign.pcap  : ${sz} bytes" | tee -a "$REPORT"

# ---------------------------------------------------------------------------
# 3) spoof.pcap —— 正常系統 + spoof_attack 匿名注入（測試用）
# ---------------------------------------------------------------------------
log "=== (2/2) Spoofing 攻擊場景：抓 ${SPOOF_SEC}s → spoof.pcap ==="
start_system "$DEST"
start_capture "$DEST/spoof.pcap"
./attacks/spoof_attack > "$DEST/spoof_attack.log" 2>&1 & ATK=$!
log "    spoof_attack 已啟動（pid $ATK），冒充 sensor 匿名注入中..."
sleep "$SPOOF_SEC"
# 先 SIGTERM 讓攻擊優雅退出（它有 handler，會 flush stdout buffer，注入記錄才不
# 會遺失）；給 1 秒後若還在才 kill -9 保底。直接 kill -9 會丟掉未 flush 的 log。
kill -TERM $ATK 2>/dev/null
for _ in 1 2 3 4 5; do kill -0 $ATK 2>/dev/null || break; sleep 0.2; done
kill -9 $ATK 2>/dev/null
stop_capture
stop_system
sz=$(stat -c%s "$DEST/spoof.pcap" 2>/dev/null || echo 0)
n_inj=$(grep -c "injected" "$DEST/spoof_attack.log" 2>/dev/null || echo 0)
{
  echo "    spoof.pcap   : ${sz} bytes"
  echo "    注入筆數     : $n_inj （spoof_attack 匿名寫入的偽造 log 行數）"
} | tee -a "$REPORT"

# ---------------------------------------------------------------------------
# 完成
# ---------------------------------------------------------------------------
{
  echo ""
  echo "============================================================"
  echo "抓取完成 → $DEST"
  echo "============================================================"
  echo "下一步："
  echo "  1) ml/venv/bin/python net/pcap_to_features.py $DEST"
  echo "     → 產生 benign_flows.csv / spoof_flows.csv（每秒 flow 統計特徵）"
  echo "  2) ml/venv/bin/python net/detect_net.py $DEST"
  echo "     → IsolationForest 在 benign 上訓練、在 spoof 上偵測，報 Precision/Recall/F1"
} | tee -a "$REPORT"

log "報告已存：$REPORT"
