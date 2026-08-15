#!/bin/bash
# =============================================================================
# capture_topo_multi.sh ── M sensor + N motor 的「多對多」拓撲採集（項目 2）
# =============================================================================
# 與 capture_topo.sh 的差異（為什麼要另開一支，而不是改舊的）：
#   舊腳本是「1 sensor → N motor」星狀，已經產出多輪可比較的資料集；直接改它會讓
#   新舊資料無法對照。這支獨立腳本專門跑放大後的拓撲，舊資料與舊結論保持有效。
#
# 拓撲（M=3, N=6 為例）：
#     sensor1(:4842)      sensor2(:4843)      sensor3(:4844)
#        ▲    ▲              ▲    ▲              ▲    ▲
#     motor1 motor4       motor2 motor5       motor3 motor6
#        └──────┴──────────────┴──────┴──────────────┴──────┘
#                     全部把 log 寫進 aggregation_server(:4840)
#
#   motor i 訂閱 sensor ((i-1) mod M) + 1 → 每台 sensor 底下有一「群」motor。
#   「該一致的那群」＝同群的 motor；這個分群關係只存在於**訂閱邊**裡。
#
# 進階攻擊 compromised_group：冒用某台 motor 的身分，回報**另一群 sensor 的真值**。
#   → 全域平特徵 report_dev_max = 0（因為那個值確實是某台 sensor 的真值）
#   → 只有「跟同群 peer 比」才看得出不一致 → 需要拓撲/圖
#   詳見 net/TOPO_SCALEUP_DESIGN.md 與 attacks/compromised_group_attack.c。
#
# 用法：
#   ./net/capture_topo_multi.sh                    # 預設 benign 300 / 攻擊 300 / 6 motor / 3 sensor
#   ./net/capture_topo_multi.sh 1800 600 6 3       # 正式（約 2 小時）
#   ./net/capture_topo_multi.sh 120 120 6 3 quick  # 流程煙霧測試
#
# ⚠️ 一律用背景執行（nohup ... &）。前景 timeout 會殺掉整個採集進程樹。
# =============================================================================
set -u

BENIGN_SEC="${1:-300}"
ATTACK_SEC="${2:-300}"
N_MOTOR="${3:-6}"
N_SENSOR="${4:-3}"
MODE="${5:-full}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

# 伺服器端的合法身分清單（封閉世界，見 aggregation_server.c resolve_source_node）
export AGG_N_MOTOR="$N_MOTOR"
export AGG_N_SENSOR="$N_SENSOR"

# 補跑支援：CAPROOT_OVERRIDE 指定既有目錄、PHASES 指定要跑哪些場景
#   （例：PHASES="simple" CAPROOT_OVERRIDE=.../topo_3s6m_xxx ./capture_topo_multi.sh 0 600 6 3）
STAMP="$(date +%Y%m%d_%H%M%S)"
CAPROOT="${CAPROOT_OVERRIDE:-$ROOT/net/captures/topo_${N_SENSOR}s${N_MOTOR}m_${STAMP}}"
PHASES="${PHASES:-all}"
# 場景流水號：各階段都會用到，但單獨補跑某個階段時前面的階段不會執行，
# 因此一定要在這裡初始化（set -u 下未初始化會直接中止）。
i=1
mkdir -p "$CAPROOT"
REPORT="$CAPROOT/report_${STAMP}.txt"

IFACE="lo"
LAST_SENSOR_PORT=$(( 4841 + N_SENSOR ))
BPF="tcp port 4840 or (tcp portrange 4842-${LAST_SENSOR_PORT})"

log() { echo "$@" | tee -a "$REPORT"; }

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
# 1) 編譯（一律重編：本實驗依賴 2a 的動態身分表與多實例改造）
# ---------------------------------------------------------------------------
echo "[multi] 編譯..."
for p in aggregation_server sensor_pub Anomaly_client; do
  gcc -o "$p" "$p.c" $UA_INC $UA_LIB 2>/tmp/multi_$p.err \
    && echo "[multi]   ✓ $p" || { echo "[multi] ✗ $p"; sed -n '1,5p' /tmp/multi_$p.err; exit 1; }
done
gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/tmp/multi_motor.err \
  && echo "[multi]   ✓ motor_sub" || { echo "[multi] ✗ motor_sub"; sed -n '1,5p' /tmp/multi_motor.err; exit 1; }

# 前置檢查：多實例身分邏輯 + 動態 SourceNode 表（2a）
grep -q "MotorSource%d" motor_sub.c || { echo "[multi] ✗ motor_sub.c 缺多實例身分"; exit 1; }
grep -q "AGG_N_MOTOR"   aggregation_server.c || {
  echo "[multi] ✗ aggregation_server.c 仍是寫死的 SOURCE_REGISTRY（3 台上限）→ 第 4 台以後會被判 null。"
  exit 1; }

if [ ! -f net/bindsrc.so ] || [ net/bindsrc.c -nt net/bindsrc.so ]; then
  gcc -shared -fPIC -o net/bindsrc.so net/bindsrc.c -ldl 2>/dev/null \
    && echo "[multi]   ✓ bindsrc.so" || { echo "[multi] ✗ bindsrc.so"; exit 1; }
fi

for a in spoof_attack repudiation_attack tamper_attack replay_attack \
         stealth_spoof_attack compromised_node_attack compromised_group_attack; do
  gcc -o "attacks/$a" -DBASELINE_SEC=$ATTACK_SEC "attacks/$a.c" $UA_INC $UA_LIB 2>/tmp/multi_$a.err \
    && echo "[multi]   ✓ $a" || { echo "[multi] ✗ $a"; sed -n '1,5p' /tmp/multi_$a.err; exit 1; }
done

kill_all() {
  ps aux | grep -E 'aggregation_server|sensor_pub|motor_sub|Anomaly_client|_attack' \
    | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 1
}
PIDS=(); CAP_PID=""
cleanup_trap() {
  echo ""; echo "[multi] 中斷，收尾中..."
  [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2>/dev/null
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  kill_all; exit 130
}
trap cleanup_trap INT TERM

# motor i 訂閱哪一台 sensor（1-based 輪流分配）
sensor_of() { echo $(( ( ($1 - 1) % N_SENSOR ) + 1 )); }

# ---------------------------------------------------------------------------
# 2) 系統啟停（M sensor + N motor）
# ---------------------------------------------------------------------------
start_system() {
  # ⚠️ 迴圈變數一律 local：bash 函式預設共用全域變數，先前這裡用了 $k / $i，
  #    把呼叫端 `for k in S T R RP` 的 k 蓋成 sensor 數 → ${ATK_BIN[$k]} 變空字串
  #    → 四個簡單攻擊**完全沒被啟動**，pcap 也被命名成 3.pcap。踩過一次，別再犯。
  local dest="$1" skip_motor="${2:-0}" si mi; PIDS=()
  ./aggregation_server > "$dest/agg.log" 2>&1 & PIDS+=($!)
  sleep 2
  for si in $(seq 1 "$N_SENSOR"); do
    ./sensor_pub "$si" > "$dest/sensor${si}.log" 2>&1 & PIDS+=($!)
  done
  sleep 2
  for mi in $(seq 1 "$N_MOTOR"); do
    [ "$mi" = "$skip_motor" ] && continue          # 空出身分給冒用者
    BIND_SRC="127.0.0.$((mi+1))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
      ./motor_sub "$mi" "$(sensor_of "$mi")" > "$dest/motor${mi}.log" 2>&1 & PIDS+=($!)
  done
  ./Anomaly_client > "$dest/anomaly.log" 2>&1 & PIDS+=($!)
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
  echo "${N_SENSOR} sensor + ${N_MOTOR} motor 多對多拓撲採集  ($STAMP)"
  echo "============================================================"
  echo "介面=$IFACE  BPF='$BPF'  工具=$CAP_CMD"
  echo "benign=${BENIGN_SEC}s  攻擊各=${ATTACK_SEC}s"
  echo "訂閱分群："
  for i in $(seq 1 "$N_MOTOR"); do echo "  motor$i → sensor$(sensor_of "$i")"; done
  echo ""
} | tee "$REPORT"

kill_all

# ---------------------------------------------------------------------------
# 3) benign
# ---------------------------------------------------------------------------
if [ "$PHASES" = "all" ] || [ "$PHASES" = "benign" ]; then
DEST="$CAPROOT/benign"; mkdir -p "$DEST"
log "=== (1) 純正常 benign：${BENIGN_SEC}s ==="
start_system "$DEST"
start_capture "$DEST/benign.pcap"
sleep "$BENIGN_SEC"
stop_capture; stop_system
report_scenario "$DEST" "benign"
log ""

fi

# ---------------------------------------------------------------------------
# 4) 四種簡單攻擊 + 並存
# ---------------------------------------------------------------------------
if [ "$PHASES" = "all" ] || [ "$PHASES" = "simple" ]; then
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

fi

# ---------------------------------------------------------------------------
# 5) stealth_spoof（每秒都寫的匿名掩護）
# ---------------------------------------------------------------------------
if [ "$PHASES" = "all" ] || [ "$PHASES" = "advanced" ] || [ "$PHASES" = "cgroup" ]; then
# 被冒用者的身分：兩個 compromised 場景都要用，因此定義在 PHASES 分支之外
# （曾經放在 compromised_node 區塊內，PHASES=cgroup 單獨補跑時就 unbound variable）
VICTIM=$N_MOTOR                       # 空出最後一台的身分給冒用者
VICTIM_SENSOR=$(sensor_of "$VICTIM")
IMPERSONATE="MotorSource${VICTIM}"

if [ "$PHASES" != "cgroup" ]; then
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
# 6) compromised_node（舊版：回報 sensor 真值 ±20）
#    留著當**對照組**：它的破綻仍可被單一 report_dev_max 平特徵表達。
# ---------------------------------------------------------------------------
DEST="$CAPROOT/compromised"; mkdir -p "$DEST"
log "=== ($i) 進階攻擊 compromised_node（冒用 $IMPERSONATE，訂閱 sensor$VICTIM_SENSOR）==="
start_system "$DEST" "$VICTIM"
start_capture "$DEST/compromised.pcap"
BIND_SRC="127.0.0.$(( VICTIM + 1 ))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
  ./attacks/compromised_node_attack "$IMPERSONATE" \
    > "$DEST/compromised_node_attack.log" 2>&1 & ATK=$!
sleep $(( ATTACK_SEC + 10 ))
kill -9 $ATK 2>/dev/null
stop_capture; stop_system
report_scenario "$DEST" "compromised"
log ""
i=$(( i + 1 ))

fi

# ---------------------------------------------------------------------------
# 7) compromised_group（新版：回報**別群 sensor 的真值**）
#    這是項目 2 的主角：平特徵看不見、只有拓撲看得見。
# ---------------------------------------------------------------------------
FOREIGN=$(( ( VICTIM_SENSOR % N_SENSOR ) + 1 ))     # 任一台不同的 sensor
DEST="$CAPROOT/compromised_group"; mkdir -p "$DEST"
log "=== ($i) 進階攻擊 compromised_group（冒用 $IMPERSONATE：own=sensor$VICTIM_SENSOR，報 sensor$FOREIGN 的值）==="
start_system "$DEST" "$VICTIM"
start_capture "$DEST/compromised_group.pcap"
# reader：**另一個來源 IP**，只訂閱別群 sensor 並寫檔（模擬攻擊者在他處的立足點）。
# 這樣主行程在圖上只有 1 條訂閱邊，與真 motor 逐邊同構 —— 否則「多一條訂閱邊」
# 本身就是不用看值就能抓到的指紋（第一版踩過，見攻擊原始碼註解）。
VALFILE="/tmp/cg_foreign_${STAMP}.val"; rm -f "$VALFILE"
BIND_SRC="127.0.0.$(( N_MOTOR + 3 ))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
  ./attacks/compromised_group_attack --reader "$FOREIGN" "$VALFILE" \
    > "$DEST/cg_reader.log" 2>&1 & RDR=$!
sleep 2
BIND_SRC="127.0.0.$(( VICTIM + 1 ))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
  ./attacks/compromised_group_attack "$IMPERSONATE" "$VICTIM_SENSOR" "$FOREIGN" "$VALFILE" \
    > "$DEST/compromised_group_attack.log" 2>&1 & ATK=$!
sleep $(( ATTACK_SEC + 10 ))
kill -9 $ATK 2>/dev/null; kill -9 $RDR 2>/dev/null; rm -f "$VALFILE"
stop_capture; stop_system
report_scenario "$DEST" "compromised_group"

fi

{
  echo ""
  echo "============================================================"
  echo "採集完成 → $CAPROOT"
  echo "============================================================"
  echo "下一步："
  echo "  ml/venv/bin/python net/build_graph.py $CAPROOT"
  echo "  ml/venv/bin/python net/graph_clf.py   $CAPROOT"
} | tee -a "$REPORT"
echo "[multi] 報告：$REPORT"
