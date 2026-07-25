#!/usr/bin/env bash
# =============================================================================
# DOS 測試共用核心（被 run_dos_A/B/C.sh 呼叫，通常不直接執行）
#
# 職責：用同一個時間戳串起一次完整測試
#   1. 起四支程式，各自寫入 <PHASE>_<TS>_{agg,sensor,motor,anomaly}.log
#   2. 開 tcpdump 抓包 → <PHASE>_<TS>.pcap（涵蓋業務 TCP + PubSub UDP + 攻擊）
#   3. 讓系統先跑 BASELINE 秒建立乾淨基準
#   4. 依序跑多檔 dos_flood.py 攻擊（輕→中→重），每檔之間插入恢復空檔
#   5. 收尾：停攻擊、停抓包、停四支程式，印出檔名與快速統計
#
# 用法（由入口腳本帶入環境變數）：
#   ATTACK_STEPS 是「一行一檔」的攻擊參數清單，會依序執行。
#   PHASE=B ATTACK_STEPS=$'B --conns 20 --dur 30 --port 4842\nB --conns 50 ...' ./dos_runner.sh
# 可調環境變數：
#   BASELINE=60   攻擊前的乾淨基準秒數（預設 60）
#   RECOVER=15    每檔攻擊之間的恢復空檔秒數（預設 15）
#   RUN_MOTOR=1   是否啟動 motor_sub（需 GPIO，預設 1；無硬體設 0）
#   PORT=4842     抓包/攻擊目標埠（預設 4842）
# =============================================================================
set -u
cd "$(dirname "$0")"

PHASE="${PHASE:?需指定 PHASE (A/B/C)}"
ATTACK_STEPS="${ATTACK_STEPS:?需指定 ATTACK_STEPS（一行一檔）}"
BASELINE="${BASELINE:-60}"
RECOVER="${RECOVER:-15}"
RUN_MOTOR="${RUN_MOTOR:-1}"
PORT="${PORT:-4842}"

TS="$(date +%H%M%S)"
PREFIX="${PHASE}_${TS}"
PCAP="${PREFIX}.pcap"

STAMP='{print strftime("[%H:%M:%S]"),$0; fflush()}'
PIDS=()            # 四支程式的 pid
TCPDUMP_PID=""

log() { echo -e "\033[1;36m[runner]\033[0m $*"; }

cleanup() {
  log "收尾中..."
  # 停攻擊子行程（若還在）
  [ -n "${ATTACK_PID:-}" ] && kill "$ATTACK_PID" 2>/dev/null
  # 停四支程式
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  # 停 tcpdump（需 sudo）
  [ -n "$TCPDUMP_PID" ] && sudo kill "$TCPDUMP_PID" 2>/dev/null
  sleep 1
  echo
  log "===== 本次測試產物（時間戳 $TS）====="
  ls -la ${PREFIX}_*.log "$PCAP" 2>/dev/null
  echo
  if [ -f "$PCAP" ]; then
    log "pcap 快速統計："
    echo "  業務廣播 (UDP 4843) : $(sudo tcpdump -r "$PCAP" -n 'udp port 4843' 2>/dev/null | wc -l) 個"
    echo "  攻擊 SYN            : $(sudo tcpdump -r "$PCAP" -n 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' 2>/dev/null | wc -l) 個"
    echo "  OPC UA Hello (HELF): $(sudo tcpdump -r "$PCAP" -A 2>/dev/null | grep -c HELF) 個"
  fi
  log "完成。log 前綴：${PREFIX}_ ，封包：${PCAP}"
  exit 0
}
trap cleanup INT TERM

# --- 1. 起四支程式 ----------------------------------------------------------
log "啟動系統，log 前綴：${PREFIX}_"
./aggregation_server 2>&1 | awk "$STAMP" > "${PREFIX}_agg.log" &
PIDS+=($!); sleep 1
./sensor_pub 2>&1 | awk "$STAMP" > "${PREFIX}_sensor.log" &
PIDS+=($!); sleep 1
if [ "$RUN_MOTOR" = "1" ]; then
  ./motor_sub 2>&1 | awk "$STAMP" > "${PREFIX}_motor.log" &
  PIDS+=($!); sleep 1
else
  log "略過 motor_sub (RUN_MOTOR=0)"
fi
./Anomaly_client 2>&1 | awk "$STAMP" > "${PREFIX}_anomaly.log" &
PIDS+=($!); sleep 2

# --- 2. 開 tcpdump 抓包（攻擊前就開）---------------------------------------
log "開始抓包 → ${PCAP}（需要 sudo 權限）"
sudo tcpdump -i any -w "$PCAP" \
  'tcp port 4840 or tcp port 4842 or tcp port 4801 or udp port 4843' \
  2>/dev/null &
TCPDUMP_PID=$!
sleep 2

# --- 3. baseline ------------------------------------------------------------
log "建立 baseline：乾淨運行 ${BASELINE} 秒（此段為正常業務基準）..."
sleep "$BASELINE"

# --- 4. 依序跑多檔攻擊（輕→中→重）------------------------------------------
STEP_NO=0
TOTAL=$(printf '%s\n' "$ATTACK_STEPS" | grep -c '[^[:space:]]')
while IFS= read -r step; do
  [ -z "${step//[[:space:]]/}" ] && continue     # 跳過空行
  STEP_NO=$((STEP_NO+1))
  log ">>> 第 ${STEP_NO}/${TOTAL} 檔攻擊：python3 dos_flood.py ${step}"
  python3 dos_flood.py ${step} &
  ATTACK_PID=$!
  wait "$ATTACK_PID"                              # 每檔有 --dur，跑完自己結束
  if [ "$STEP_NO" -lt "$TOTAL" ]; then
    log "第 ${STEP_NO} 檔結束，恢復空檔 ${RECOVER} 秒（觀察系統是否回穩）..."
    sleep "$RECOVER"
  fi
done <<< "$ATTACK_STEPS"

log "全部 ${TOTAL} 檔攻擊結束，再抓 5 秒觀察最終恢復..."
sleep 5

# --- 5. 收尾 ----------------------------------------------------------------
cleanup
