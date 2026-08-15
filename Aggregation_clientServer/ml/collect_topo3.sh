#!/bin/bash
# =============================================================================
# collect_topo3.sh ── 【實驗1】三組 1-對-1 pair、匯進同一 aggregation_server
# =============================================================================
# 拓樸（相對 collect_v2.sh 的單一 pair）：
#   pair i = sensor_pub i  (serve @ 4841+i, session SensorSource<i>)
#          + motor_sub i i (訂閱 sensor i, session MotorSource<i>)
#   三組 pair 的 log 全部寫進『同一個』aggregation_server@4840 的 CentralLogIn，
#   由 server 依 session 身分蓋 SourceNode=ns=1;s=SensorSource{1..3}/MotorSource{1..3}。
#   → 已用 smoke test 驗證：C 程式無須改動，AGG_N_SENSOR/AGG_N_MOTOR 即可開。
#
# 攻擊比例維持原狀（每 pair 的注入密度與單 pair 實驗相同）：
#   benign 流量 ×3（三 pair）→ 攻擊也 ×3 才能維持比例。做法：
#     - spoof/repudiation/replay 打中央 4840（不分 pair）→ 開 3 份並行實例。
#     - tamper 打 sensor port → 分別指到 4842/4843/4844（tamper_attack <sid> 已支援）。
#
# ⚠ 資料分析注意（採集後必看）：三 sensor 併發 → benign 每秒本就有 ~3 筆 sensor 行，
#   ml/parse_logs.py 的 sensor_events_in_sec 是『全域計數』，會被 3 sensor 灌成常態 3，
#   使 S(spoof) 的「同秒雙報」特徵失效。採集後需把該特徵改成 **per-SourceName** 計數
#   （每個 sensor 各自每秒幾筆）。這是本實驗刻意要壓測的難點，不是 bug。
#
# 用法：
#   ./ml/collect_topo3.sh                 # baseline 60min + benign×2 + FC×10 + R×10
#   ./ml/collect_topo3.sh 10 2 2 1        # 短測：baseline分 FC輪 R輪 benign輪
# =============================================================================
set -u

MINUTES="${1:-60}"
N_FC="${2:-10}"
N_R="${3:-10}"
N_BENIGN="${4:-2}"
N_PAIR=3
ATTACK_SEC=300

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
LOGROOT="$ROOT/attacks/logs"
REPORT="$LOGROOT/topo3_collection_report_${STAMP}.txt"

# ---------------------------------------------------------------------------
# 0) 編譯
# ---------------------------------------------------------------------------
echo "[topo3] === 編譯 ==="
for p in aggregation_server sensor_pub Anomaly_client; do
  if [ ! -x "$p" ] || [ "$p.c" -nt "$p" ]; then
    gcc -o "$p" "$p.c" $UA_INC $UA_LIB 2>/tmp/t3_$p.err \
      && echo "[topo3]   ✓ $p" \
      || { echo "[topo3]   ✗ $p:"; sed -n '1,5p' /tmp/t3_$p.err; exit 1; }
  fi
done
HAVE_MOTOR=1
if [ ! -x motor_sub ] || [ motor_sub.c -nt motor_sub ]; then
  gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/dev/null \
    && echo "[topo3]   ✓ motor_sub" \
    || { HAVE_MOTOR=0; echo "[topo3]   ⚠ motor_sub 編不起來"; }
fi
if [ "$HAVE_MOTOR" = "0" ]; then
  echo "[topo3] ✗ 三 pair 拓樸必須有 motor（否則 R 洩漏修正失效）。中止。"; exit 1
fi
for a in repudiation_attack spoof_attack tamper_attack replay_attack; do
  gcc -o "attacks/$a" "attacks/$a.c" $UA_INC $UA_LIB 2>/dev/null \
    && echo "[topo3]   ✓ $a" || { echo "[topo3]   ✗ $a"; exit 1; }
done

kill_all() {
  ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client|_attack' | grep -v grep \
    | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 2
}
PIDS=()
trap 'echo "[topo3] 中斷"; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; kill_all; exit 130' INT TERM

# ground-truth 標記：呼叫 ml/mark_anomalies.py（與 collect_v2.sh 同一標準）。
# ⚠ parse_logs.py 是『讀』anomaly_marked.log 取標籤，不會自己生標籤，所以採集後
#   必須產生 marked 檔，否則該場景會被當成全正常（早期版本漏了這步的教訓）。
make_marked() {
  local dest="$1"
  ml/venv/bin/python ml/mark_anomalies.py "$dest" 2>/dev/null \
    || python3 ml/mark_anomalies.py "$dest"
}

# ---------------------------------------------------------------------------
# 三 pair 系統起停
# ---------------------------------------------------------------------------
start_system() {
  local dest="$1"; PIDS=()
  AGG_N_SENSOR=$N_PAIR AGG_N_MOTOR=$N_PAIR ./aggregation_server > "$dest/agg.log" 2>&1 & PIDS+=($!)
  sleep 3
  for i in $(seq 1 $N_PAIR); do
    ./sensor_pub "$i" > "$dest/sensor${i}.log" 2>&1 & PIDS+=($!)
  done
  sleep 2
  for i in $(seq 1 $N_PAIR); do
    ./motor_sub "$i" "$i" > "$dest/motor${i}.log" 2>&1 & PIDS+=($!)
  done
  ./Anomaly_client > "$dest/anomaly.log" 2>&1 & PIDS+=($!)
  sleep 3
}
stop_system() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  sleep 2; kill_all
}

report_scenario() {
  local dest="$1" scen="$2"
  {
    echo "--- $scen"
    echo "    總行數           : $(grep -c 'Anomaly Input' "$dest/anomaly.log" 2>/dev/null || echo 0)"
    echo "    SourceNode = null: $(grep -c 'SourceNode=null' "$dest/anomaly.log" 2>/dev/null || echo 0)"
    for i in $(seq 1 $N_PAIR); do
      echo "    SensorSource$i    : $(grep -c "SourceNode=ns=1;s=SensorSource$([ $i -eq 1 ] && echo '' || echo $i)\b" "$dest/anomaly.log" 2>/dev/null || echo 0)"
    done
  } | tee -a "$REPORT"
}

echo "" | tee "$REPORT"
echo "============================================================" | tee -a "$REPORT"
echo "【實驗1】三 pair 拓樸採集報告 ($STAMP)" | tee -a "$REPORT"
echo "  baseline ${MINUTES}分 · benign×${N_BENIGN} · FC×${N_FC} · R×${N_R}  (每場景 3 pair)" | tee -a "$REPORT"
echo "============================================================" | tee -a "$REPORT"
kill_all

# ---------------------------------------------------------------------------
# 1) baseline（純正常，三 pair）
# ---------------------------------------------------------------------------
DEST="$LOGROOT/topo3_baseline_${MINUTES}min_${STAMP}"; mkdir -p "$DEST"
echo "[topo3] === (1) baseline ${MINUTES} 分 ==="
start_system "$DEST"
elapsed=0; DUR=$(( MINUTES * 60 ))
while [ "$elapsed" -lt "$DUR" ]; do
  sleep 60; elapsed=$(( elapsed + 60 ))
  echo "[topo3]     ${elapsed}s/${DUR}s  行數=$(grep -c 'Anomaly Input' "$DEST/anomaly.log" 2>/dev/null || echo 0)"
done
stop_system; make_marked "$DEST"; report_scenario "$DEST" "$(basename "$DEST")"; echo ""

# ---------------------------------------------------------------------------
# 1b) benign 對照（同 harness、關注入，三 pair）—— 命名以 topo3_baseline 開頭
# ---------------------------------------------------------------------------
for i in $(seq 1 "$N_BENIGN"); do
  DEST="$LOGROOT/topo3_baseline_ctrl_r${i}_${STAMP}"; mkdir -p "$DEST"
  echo "[topo3] === (1b.$i/$N_BENIGN) benign 對照 (${ATTACK_SEC}s) ==="
  start_system "$DEST"; sleep $(( ATTACK_SEC + 10 )); stop_system
  make_marked "$DEST"
  report_scenario "$DEST" "$(basename "$DEST")"; echo ""
done

# ---------------------------------------------------------------------------
# 2) Four_combined × N：攻擊 ×3 維持比例
#    spoof/repud/replay 各開 3 份打中央 4840；tamper 分別打 4842/4843/4844。
# ---------------------------------------------------------------------------
for i in $(seq 1 "$N_FC"); do
  DEST="$LOGROOT/topo3_Four_combined_r${i}_${STAMP}"; mkdir -p "$DEST"
  echo "[topo3] === (2.$i/$N_FC) Four_combined ×3 pair (${ATTACK_SEC}s) ==="
  start_system "$DEST"
  ATK=()
  # 每支攻擊都指定 pair k，讓四種攻擊都均勻覆蓋三組 pair。
  #   spoof/repudiation "$k" → 偽造內容自稱 Sensor<k>/Motor<k>（打中央 4840）。
  #   replay "$k"            → 鎖定側錄 pair k 的 sensor 事件再重放（打中央 4840）。
  #   tamper "$k"            → 打 sensor k 的 port 4841+k。
  # 修正前：前三支不吃參數，三份實例的偽造身分全部落在 pair1，pair3 永遠沒有攻擊。
  for k in 1 2 3; do
    ./attacks/spoof_attack       "$k" > "$DEST/spoof_attack_p${k}.log"       2>&1 & ATK+=($!)
    ./attacks/repudiation_attack "$k" > "$DEST/repudiation_attack_p${k}.log" 2>&1 & ATK+=($!)
    ./attacks/replay_attack      "$k" > "$DEST/replay_attack_p${k}.log"      2>&1 & ATK+=($!)
    ./attacks/tamper_attack      "$k" > "$DEST/tamper_attack_p${k}.log"      2>&1 & ATK+=($!)
  done
  sleep $(( ATTACK_SEC + 10 ))
  for p in "${ATK[@]}"; do kill -9 "$p" 2>/dev/null; done
  stop_system; make_marked "$DEST"; report_scenario "$DEST" "$(basename "$DEST")"; echo ""
done

# ---------------------------------------------------------------------------
# 3) R_only × N：三 pair 各一份 repudiation
# ---------------------------------------------------------------------------
for i in $(seq 1 "$N_R"); do
  DEST="$LOGROOT/topo3_R_only_r${i}_${STAMP}"; mkdir -p "$DEST"
  echo "[topo3] === (3.$i/$N_R) R_only ×3 (${ATTACK_SEC}s) ==="
  start_system "$DEST"
  ATK=()
  for k in 1 2 3; do ./attacks/repudiation_attack "$k" > "$DEST/repudiation_attack_p${k}.log" 2>&1 & ATK+=($!); done
  sleep $(( ATTACK_SEC + 10 ))
  for p in "${ATK[@]}"; do kill -9 "$p" 2>/dev/null; done
  stop_system; make_marked "$DEST"; report_scenario "$DEST" "$(basename "$DEST")"; echo ""
done

{
  echo ""
  echo "============================================================"
  echo "採集完成 —— 下一步"
  echo "============================================================"
  echo "  # ⚠ 先改 parse_logs.py 的 sensor_events_in_sec 為 per-SourceName 計數，"
  echo "  #   否則三 sensor 併發會讓 S 特徵失效（見本檔頂部說明）。"
  echo "  ml/venv/bin/python ml/parse_logs.py"
  echo "  SCENARIO_FILTER=topo3_${STAMP} ml/venv/bin/python ml/ngram_detector.py"
  echo "  SCENARIO_FILTER=topo3_${STAMP} ml/venv/bin/python ml/compare_ngram_deeplog.py"
  echo ""
  echo "驗收：benign 應含三 sensor 的 SourceNode=ns=1;s=SensorSource{,2,3}；"
  echo "      benign_ctrl 的 SourceNode=null 應為 0。"
} | tee -a "$REPORT"
echo "[topo3] 報告已存：$REPORT"
