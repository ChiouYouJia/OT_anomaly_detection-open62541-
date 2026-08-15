#!/bin/bash
# =============================================================================
# capture_topo_rotate.sh ── 動態訂閱拓撲採集（第三輪 TODO 的 3-4）
# =============================================================================
# 要回答的問題：
#   第三輪的規則堆疊實驗顯示，一條零訓練規則 D5（report_dev_own > 0.1）在
#   compromised 與 compromised_group 上都是 recall 100% / benign 零誤報，
#   而 GNN 在告警路徑上毫無貢獻。所以「GNN 相對人工特徵有價值」這個主張
#   在**靜態拓撲**下已經站不住。
#
#   但 D5 有一個沒被檢驗的前提：**每台 motor 訂閱哪一台 sensor，整段採集中固定不變**。
#   build_graph.py 目前正是這樣做的 —— 它從 pcap 觀察 motor 的連線目的 port，
#   建出**一張全域靜態**的 motor→sensor 對照表（node2sensor / sess2sensor）。
#   本場景讓訂閱關係在採集期間**週期性輪換**，於是：
#     · 那張靜態表在絕大部分時間是錯的 → D5 靜默失效（不會報錯，只是抓不到）
#     · GNN 從**當下這一秒的訂閱邊**做訊息傳遞 → 不需要任何對照表
#
# ⚠️ 這個實驗證明的**不是**「規則不可能做到」——
#   規則當然可以改成逐秒重算對照表（本輪也會實作 report_dev_own_dyn 當作
#   誠實的強基線）。它證明的是：**規則需要一份正確且持續維護的拓撲模型，
#   而 GNN 不需要**。拓撲一變，規則靜默失效；GNN 只用 benign 訓練就跟著走。
#   報告時請照這個範圍寫，不要寫成「規則做不到」。
#
# ── 怎麼做到輪換（不改任何 C 程式碼）────────────────────────────────────────
#   motor_sub 已經吃 argv[2] = sensor_id。因此輪換用「殺掉並以新 sensor_id 重啟」
#   即可，零 C 改動。每 ROTATE_SEC 秒，全部 motor 同時輪換一格：
#       motor i → sensor ((i-1+off) mod N_SENSOR) + 1 ，off = 0,1,2,...
#   **所有 motor（含冒用者）一起輪換**，所以重啟造成的連線抖動（SYN/FIN）對每個
#   節點都一樣 → 不會變成「只有攻擊者會重連」這種不用看值就抓得到的指紋。
#   （這類自我製造的指紋在 compromised_group 第一版踩過，見該攻擊原始碼註解。）
#
#   攻擊沿用 attacks/compromised_group_attack（冒用合法身分、回報別群 sensor 的
#   真值），但**每個輪換時段重啟一次**並帶入該時段新的 own/foreign sensor id。
#   為了讓注入密度與既有資料集可比（20 次 / 600 秒），攻擊另外編一份
#   BASELINE_SEC=ROTATE_SEC、N_TAMPER=20/時段數 的執行檔。
#
# 用法：
#   ./net/capture_topo_rotate.sh                          # 預設 benign 300 / 攻擊 300 / 6 motor / 3 sensor / 輪換 60s
#   ./net/capture_topo_rotate.sh 1800 600 6 3 120         # 正式（約 40 分鐘）
#   ./net/capture_topo_rotate.sh 120 120 6 3 30 quick     # 流程煙霧測試
#
# ⚠️ 一律用背景執行（nohup ... &）。前景 timeout 會殺掉整個採集進程樹（踩過）。
# =============================================================================
set -u

BENIGN_SEC="${1:-300}"
ATTACK_SEC="${2:-300}"
N_MOTOR="${3:-6}"
N_SENSOR="${4:-3}"
ROTATE_SEC="${5:-60}"
MODE="${6:-full}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"
export AGG_N_MOTOR="$N_MOTOR"
export AGG_N_SENSOR="$N_SENSOR"

STAMP="$(date +%Y%m%d_%H%M%S)"
CAPROOT="${CAPROOT_OVERRIDE:-$ROOT/net/captures/rot_${N_SENSOR}s${N_MOTOR}m_${STAMP}}"
PHASES="${PHASES:-all}"
mkdir -p "$CAPROOT"
REPORT="$CAPROOT/report_${STAMP}.txt"

IFACE="lo"
LAST_SENSOR_PORT=$(( 4841 + N_SENSOR ))
BPF="tcp port 4840 or (tcp portrange 4842-${LAST_SENSOR_PORT})"

# 每個攻擊場景會經歷幾個輪換時段（至少 1）
SLOTS=$(( ATTACK_SEC / ROTATE_SEC )); [ "$SLOTS" -lt 1 ] && SLOTS=1
TAMPER_PER_SLOT=$(( 20 / SLOTS )); [ "$TAMPER_PER_SLOT" -lt 1 ] && TAMPER_PER_SLOT=1

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
# 1) 編譯
# ---------------------------------------------------------------------------
echo "[rot] 編譯..."
for p in aggregation_server sensor_pub Anomaly_client; do
  gcc -o "$p" "$p.c" $UA_INC $UA_LIB 2>/tmp/rot_$p.err \
    && echo "[rot]   ✓ $p" || { echo "[rot] ✗ $p"; sed -n '1,5p' /tmp/rot_$p.err; exit 1; }
done
gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/tmp/rot_motor.err \
  && echo "[rot]   ✓ motor_sub" || { echo "[rot] ✗ motor_sub"; sed -n '1,5p' /tmp/rot_motor.err; exit 1; }

grep -q "MotorSource%d" motor_sub.c || { echo "[rot] ✗ motor_sub.c 缺多實例身分"; exit 1; }
grep -q "AGG_N_MOTOR"   aggregation_server.c || {
  echo "[rot] ✗ aggregation_server.c 仍是寫死的 SOURCE_REGISTRY → 第 4 台以後會被判 null。"; exit 1; }

if [ ! -f net/bindsrc.so ] || [ net/bindsrc.c -nt net/bindsrc.so ]; then
  gcc -shared -fPIC -o net/bindsrc.so net/bindsrc.c -ldl 2>/dev/null \
    && echo "[rot]   ✓ bindsrc.so" || { echo "[rot] ✗ bindsrc.so"; exit 1; }
fi

# 攻擊：每個輪換時段重啟一次 → BASELINE_SEC 設成 ROTATE_SEC，注入數按時段分攤
gcc -o attacks/compromised_rotate_attack \
    -DBASELINE_SEC=$ROTATE_SEC -DN_TAMPER=$TAMPER_PER_SLOT \
    attacks/compromised_group_attack.c $UA_INC $UA_LIB 2>/tmp/rot_atk.err \
  && echo "[rot]   ✓ compromised_rotate_attack (每時段 ${TAMPER_PER_SLOT} 次注入 × ${SLOTS} 時段)" \
  || { echo "[rot] ✗ compromised_rotate_attack"; sed -n '1,5p' /tmp/rot_atk.err; exit 1; }

kill_all() {
  ps aux | grep -E 'aggregation_server|sensor_pub|motor_sub|Anomaly_client|_attack' \
    | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 1
}
PIDS=(); MOTOR_PIDS=(); CAP_PID=""; ATK=""; RDR=""
cleanup_trap() {
  echo ""; echo "[rot] 中斷，收尾中..."
  [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2>/dev/null
  for p in "${PIDS[@]:-}" "${MOTOR_PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  kill_all; exit 130
}
trap cleanup_trap INT TERM

# 輪換 off 格之後，motor $1 訂閱哪一台 sensor
sensor_of() { echo $(( ( ($1 - 1 + $2) % N_SENSOR ) + 1 )); }

# ---------------------------------------------------------------------------
# 2) 系統啟停 —— motor 與其餘元件分開管理，因為只有 motor 要被反覆重啟
# ---------------------------------------------------------------------------
start_backend() {
  local dest="$1" si; PIDS=()
  ./aggregation_server > "$dest/agg.log" 2>&1 & PIDS+=($!)
  sleep 2
  for si in $(seq 1 "$N_SENSOR"); do
    ./sensor_pub "$si" > "$dest/sensor${si}.log" 2>&1 & PIDS+=($!)
  done
  sleep 2
  ./Anomaly_client > "$dest/anomaly.log" 2>&1 & PIDS+=($!)
  sleep 1
}

# 以輪換偏移 $2 啟動全部 motor（$3 = 要空出身分的 motor，給冒用者用）
start_motors() {
  local dest="$1" off="$2" skip="${3:-0}" mi
  MOTOR_PIDS=()
  for mi in $(seq 1 "$N_MOTOR"); do
    [ "$mi" = "$skip" ] && continue
    BIND_SRC="127.0.0.$((mi+1))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
      ./motor_sub "$mi" "$(sensor_of "$mi" "$off")" >> "$dest/motor${mi}.log" 2>&1 &
    MOTOR_PIDS+=($!)
  done
  sleep 2
}
stop_motors() { for p in "${MOTOR_PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; MOTOR_PIDS=(); sleep 1; }
stop_backend() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; PIDS=(); sleep 1; kill_all; }

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

# 把每個時段的真實訂閱對照表寫檔 —— 這是**評估用的 ground truth**，
# 偵測器不得讀取（就像 #MAL 記號一樣）。用途是驗證輪換真的發生了，
# 以及讓 report_dev_own_dyn 的實作有東西可以對答案。
write_topology_truth() {
  local dest="$1" off="$2" t0="$3" mi
  for mi in $(seq 1 "$N_MOTOR"); do
    echo "$t0 $off motor$mi sensor$(sensor_of "$mi" "$off")" >> "$dest/topology_truth.txt"
  done
}

{
  echo "============================================================"
  echo "動態訂閱拓撲採集 rot_${N_SENSOR}s${N_MOTOR}m  ($STAMP)"
  echo "============================================================"
  echo "介面=$IFACE  BPF='$BPF'  工具=$CAP_CMD"
  echo "benign=${BENIGN_SEC}s  攻擊=${ATTACK_SEC}s  輪換週期=${ROTATE_SEC}s（${SLOTS} 個時段）"
  echo "輪換表："
  for o in $(seq 0 $(( N_SENSOR - 1 ))); do
    printf "  off=%d :" "$o"
    for i in $(seq 1 "$N_MOTOR"); do printf " m%d→s%d" "$i" "$(sensor_of "$i" "$o")"; done
    echo ""
  done
  echo ""
} | tee "$REPORT"

kill_all

# ---------------------------------------------------------------------------
# 3) benign_rot：正常運轉 + 輪換（GNN 的訓練資料，必須含輪換才學得到它是正常的）
# ---------------------------------------------------------------------------
if [ "$PHASES" = "all" ] || [ "$PHASES" = "benign" ]; then
DEST="$CAPROOT/benign"; mkdir -p "$DEST"
log "=== (1) benign + 輪換：${BENIGN_SEC}s ==="
start_backend "$DEST"
start_capture "$DEST/benign.pcap"
B_SLOTS=$(( BENIGN_SEC / ROTATE_SEC )); [ "$B_SLOTS" -lt 1 ] && B_SLOTS=1
for k in $(seq 0 $(( B_SLOTS - 1 ))); do
  OFF=$(( k % N_SENSOR ))
  write_topology_truth "$DEST" "$OFF" "$(date +%s)"
  log "    [slot $k] off=$OFF"
  start_motors "$DEST" "$OFF"
  sleep "$ROTATE_SEC"
  stop_motors
done
stop_capture; stop_backend
report_scenario "$DEST" "benign"
log ""
fi

# ---------------------------------------------------------------------------
# 4) compromised_rot：冒用合法身分 + 回報別群 sensor 真值 + 訂閱關係持續輪換
# ---------------------------------------------------------------------------
if [ "$PHASES" = "all" ] || [ "$PHASES" = "attack" ]; then
VICTIM=$N_MOTOR                          # 空出最後一台的身分給冒用者
IMPERSONATE="MotorSource${VICTIM}"
DEST="$CAPROOT/compromised_rot"; mkdir -p "$DEST"
log "=== (2) compromised_rot（冒用 $IMPERSONATE，own/foreign 每 ${ROTATE_SEC}s 跟著輪換）==="
start_backend "$DEST"
start_capture "$DEST/compromised_rot.pcap"
VALFILE="/tmp/rot_foreign_${STAMP}.val"
for k in $(seq 0 $(( SLOTS - 1 ))); do
  OFF=$(( k % N_SENSOR ))
  OWN=$(sensor_of "$VICTIM" "$OFF")
  FOREIGN=$(( ( OWN % N_SENSOR ) + 1 ))   # 任一台不同的 sensor（同樣會隨輪換改變）
  write_topology_truth "$DEST" "$OFF" "$(date +%s)"
  log "    [slot $k] off=$OFF  冒用者 own=sensor$OWN  報 sensor$FOREIGN 的值"
  rm -f "$VALFILE"
  start_motors "$DEST" "$OFF" "$VICTIM"
  # reader：另一個來源 IP，只訂閱別群 sensor 並寫檔 → 主行程在圖上只有 1 條訂閱邊，
  # 與真 motor 逐邊同構（否則「多一條訂閱邊」本身就是不用看值的指紋）。
  BIND_SRC="127.0.0.$(( N_MOTOR + 3 ))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
    ./attacks/compromised_rotate_attack --reader "$FOREIGN" "$VALFILE" \
      >> "$DEST/cg_reader.log" 2>&1 & RDR=$!
  sleep 2
  BIND_SRC="127.0.0.$(( VICTIM + 1 ))" LD_PRELOAD="$ROOT/net/bindsrc.so" \
    ./attacks/compromised_rotate_attack "$IMPERSONATE" "$OWN" "$FOREIGN" "$VALFILE" \
      >> "$DEST/compromised_rotate_attack.log" 2>&1 & ATK=$!
  sleep "$ROTATE_SEC"
  kill -9 $ATK 2>/dev/null; kill -9 $RDR 2>/dev/null
  stop_motors
done
rm -f "$VALFILE"
stop_capture; stop_backend
report_scenario "$DEST" "compromised_rot"
fi

{
  echo ""
  echo "============================================================"
  echo "採集完成 → $CAPROOT"
  echo "============================================================"
  echo "輪換是否真的發生（每台 motor 應出現多個目的 port）："
  echo "  ml/venv/bin/python net/build_graph.py $CAPROOT"
  echo ""
  echo "下一步（build_graph 需先支援 report_dev_own_dyn，見 TODO 3-4）："
  echo "  ml/venv/bin/python net/graph_clf.py    $CAPROOT"
  echo "  ml/venv/bin/python net/gnn_ablation.py $CAPROOT"
} | tee -a "$REPORT"
echo "[rot] 報告：$REPORT"
