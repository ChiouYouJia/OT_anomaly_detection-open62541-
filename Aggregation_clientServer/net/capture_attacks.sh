#!/bin/bash
# =============================================================================
# capture_attacks.sh ── 對 R/T/RP/S 各種攻擊抓網路流量（供 ML 異常檢測）
# =============================================================================
# 是 capture_spoof.sh 的通用版：可指定攻擊類型，抓取涵蓋 4840+4842 兩個 OPC UA
# server 的流量（capture_spoof.sh 只抓 4840，會漏掉打 4842 的 T(篡改)攻擊）。
#
# 各攻擊在網路層的行為（決定流量特徵抓不抓得到，見 net/README.md 的誠實評估）：
#   S  spoof       : 匿名連 4840，寫 CentralLogIn                 → 多一條連線
#   R  repudiation : 匿名連 4840，寫 CentralLogIn（與 S 幾乎同）  → 多一條連線
#   T  tamper      : 匿名連 4842，read + 寫唯讀節點被拒            → 多一條連線 + 被拒回應
#   RP replay      : 匿名連 4840，先 read 整個 CentralLog 再重寫   → 多一條連線 + 大 read 回應
#
# 用法：
#   ./net/capture_attacks.sh R              # 否認，benign 120s + 攻擊 120s
#   ./net/capture_attacks.sh T 300 300      # 篡改，各 5 分鐘
#   ./net/capture_attacks.sh RP 300 300     # 重放
#   ./net/capture_attacks.sh all 300 300    # 四攻擊同時（混合場景）
#   第4參數 quick：縮短攻擊潛伏期以確保注入落在抓取窗內（流程驗證用）
#
# 產出 net/captures/<atk>_<STAMP>/：benign.pcap, attack.pcap, 各程式 log，
# 供 net/pcap_to_features.py 與 net/detect_net.py 使用。
#
# ⚠️ 僅用於你自己機器上、你自己系統的授權安全測試。
# =============================================================================
set -u

ATK_KIND="${1:-}"                       # S | R | T | RP | all
BENIGN_SEC="${2:-120}"
ATTACK_SEC="${3:-120}"
MODE="${4:-full}"                       # full | quick

case "$ATK_KIND" in
  S|R|T|RP|all) ;;
  *) echo "用法：$0 <S|R|T|RP|all> [benign_sec] [attack_sec] [quick]"; exit 1 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

IFACE="lo"
# 同時抓兩個 OPC UA server：4840(aggregation) + 4842(sensor)。T 打 4842，其餘打 4840，
# 混合場景兩者都要。抓寬一點不影響單攻擊評估（特徵會分埠統計）。
BPF="tcp port 4840 or tcp port 4842"

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
CAPROOT="$HERE/captures"
LABEL="$(echo "$ATK_KIND" | tr 'A-Z' 'a-z')"
DEST="$CAPROOT/${LABEL}_${STAMP}"
mkdir -p "$DEST"
REPORT="$DEST/capture_report.txt"

log() { echo "[cap] $*"; }

# ---------------------------------------------------------------------------
# 0) 權限檢查（同 capture_spoof.sh：-c 1 + 戳 loopback 產生流量）
# ---------------------------------------------------------------------------
CAP_CMD=""
probe() {
  local tool="$1"
  if [ "$tool" = "tcpdump" ]; then
    timeout 3 tcpdump -i "$IFACE" -c 1 -w /dev/null >/dev/null 2>&1 & local pp=$!
  else
    timeout 3 dumpcap -i "$IFACE" -c 1 -w /dev/null >/dev/null 2>&1 & local pp=$!
  fi
  sleep 0.3
  ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1
  wait "$pp" 2>/dev/null; return $?
}
if probe tcpdump; then
  CAP_CMD="tcpdump"
elif command -v dumpcap >/dev/null 2>&1 && probe dumpcap; then
  CAP_CMD="dumpcap"
else
  cat <<EOF
[cap] ✗ 目前無權限在 $IFACE 上抓包。做一次性授權（擇一），之後免 sudo：
      sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
      sudo usermod -aG wireshark $USER    # 需登出再登入
EOF
  exit 2
fi
log "抓包工具：$CAP_CMD（$IFACE, '$BPF'）"

# ---------------------------------------------------------------------------
# 1) 建置：主系統 + 需要的攻擊程式
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

# 攻擊潛伏期綁定抓取窗，確保注入落在窗內（否則 300s 潛伏但只抓 120s → 零注入）。
N_INJ=8
[ "$ATTACK_SEC" -ge 240 ] && N_INJ=12
# 各攻擊原始碼的注入筆數巨集名稱不同：S/RP=N_INJECT/N_REPLAY、R=N_FORGE、T=N_WRITES。
# 統一都傳 BASELINE_SEC；筆數巨集則各自帶，未定義的會被忽略。
COMMON_FLAG="-DBASELINE_SEC=$ATTACK_SEC"
declare -A INJ_FLAG=(
  [spoof_attack]="-DN_INJECT=$N_INJ"
  [repudiation_attack]="-DN_FORGE=$N_INJ"
  [tamper_attack]="-DN_WRITES=$N_INJ"
  [replay_attack]="-DN_REPLAY=$N_INJ"
)
# 依攻擊類型決定要編哪些
case "$ATK_KIND" in
  S)  ATTACKS=(spoof_attack) ;;
  R)  ATTACKS=(repudiation_attack) ;;
  T)  ATTACKS=(tamper_attack) ;;
  RP) ATTACKS=(replay_attack) ;;
  all) ATTACKS=(spoof_attack repudiation_attack tamper_attack replay_attack) ;;
esac
for a in "${ATTACKS[@]}"; do
  flags="$COMMON_FLAG ${INJ_FLAG[$a]}"
  gcc -o "attacks/$a" $flags "attacks/$a.c" $UA_INC $UA_LIB 2>/tmp/cap_build_$a.err \
    && log "  ✓ $a ($flags)" \
    || { log "  ✗ $a 編譯失敗"; sed -n '1,5p' /tmp/cap_build_$a.err; exit 1; }
done

# ---------------------------------------------------------------------------
# 進程管理（同 capture_spoof.sh）
# ---------------------------------------------------------------------------
kill_all() {
  # 注意：pattern 必須精確到攻擊執行檔，不能用 '_attack'——那會匹配本腳本自己的
  # 檔名 capture_attacks.sh 而把自己 kill 掉。用各攻擊執行檔的完整名稱。
  ps aux \
    | grep -E 'aggregation_server|sensor_pub|motor_sub|Anomaly_client|spoof_attack|repudiation_attack|tamper_attack|replay_attack' \
    | grep -v grep | grep -v 'capture_attacks' \
    | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 1
}
PIDS=(); CAP_PID=""; ATK_PIDS=()
cleanup_trap() {
  echo ""; log "中斷，收尾中..."
  for p in "${ATK_PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null; done
  [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2>/dev/null
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  kill_all; exit 130
}
trap cleanup_trap INT TERM

start_system() {
  local dest="$1"; PIDS=()
  ./aggregation_server > "$dest/agg.log"     2>&1 & PIDS+=($!)
  sleep 2
  ./sensor_pub         > "$dest/sensor.log"  2>&1 & PIDS+=($!)
  [ "$HAVE_MOTOR" = "1" ] && { ./motor_sub > "$dest/motor.log" 2>&1 & PIDS+=($!); }
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

{
  echo "============================================================"
  echo "攻擊[$ATK_KIND] + 網路流量抓取報告  ($STAMP)"
  echo "============================================================"
  echo "介面=$IFACE  BPF='$BPF'  工具=$CAP_CMD"
  [ "$HAVE_MOTOR" = "0" ] && echo "註：本機無 GPIO，motor_sub 未啟動。"
  echo ""
} | tee "$REPORT"

kill_all

# ---------------------------------------------------------------------------
# 2) benign.pcap
# ---------------------------------------------------------------------------
log "=== (1/2) 純正常 baseline：抓 ${BENIGN_SEC}s → benign.pcap ==="
log "    ⚠️ 這段請勿執行任何攻擊程式"
start_system "$DEST"
start_capture "$DEST/benign.pcap"
sleep "$BENIGN_SEC"
stop_capture; stop_system
sz=$(stat -c%s "$DEST/benign.pcap" 2>/dev/null || echo 0)
echo "    benign.pcap  : ${sz} bytes" | tee -a "$REPORT"

# ---------------------------------------------------------------------------
# 3) attack.pcap
# ---------------------------------------------------------------------------
log "=== (2/2) 攻擊[$ATK_KIND] 場景：抓 ${ATTACK_SEC}s → attack.pcap ==="
start_system "$DEST"
start_capture "$DEST/attack.pcap"
ATK_PIDS=()
for a in "${ATTACKS[@]}"; do
  ./attacks/"$a" > "$DEST/$a.log" 2>&1 & ATK_PIDS+=($!)
  log "    $a 已啟動（pid ${ATK_PIDS[-1]}）"
done
sleep "$ATTACK_SEC"
# 先 SIGTERM 讓攻擊優雅退出並 flush stdout（否則 kill -9 會丟注入記錄）；再保底 kill -9
for p in "${ATK_PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
for _ in 1 2 3 4 5; do
  still=0; for p in "${ATK_PIDS[@]}"; do kill -0 "$p" 2>/dev/null && still=1; done
  [ "$still" = "0" ] && break; sleep 0.2
done
for p in "${ATK_PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
stop_capture; stop_system
sz=$(stat -c%s "$DEST/attack.pcap" 2>/dev/null || echo 0)
echo "    attack.pcap  : ${sz} bytes" | tee -a "$REPORT"
for a in "${ATTACKS[@]}"; do
  n=$(grep -cE "injected|forged|tamper|replay|Replayed|Forged" "$DEST/$a.log" 2>/dev/null || echo 0)
  echo "    $a 注入/嘗試 : $n" | tee -a "$REPORT"
done

# ---------------------------------------------------------------------------
# 完成
# ---------------------------------------------------------------------------
{
  echo ""
  echo "============================================================"
  echo "抓取完成 → $DEST"
  echo "============================================================"
  echo "下一步："
  echo "  ml/venv/bin/python net/pcap_to_features.py $DEST"
  echo "  ml/venv/bin/python net/detect_net.py       $DEST"
} | tee -a "$REPORT"
log "報告已存：$REPORT"
