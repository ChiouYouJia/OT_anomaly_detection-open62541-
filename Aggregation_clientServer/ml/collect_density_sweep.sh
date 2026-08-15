#!/bin/bash
# =============================================================================
# collect_density_sweep.sh ── 【實驗2】攻擊密度敏感度掃描（單 pair 拓樸）
# =============================================================================
# 目的（使用者確認）：「就是想看比例的影響」——把攻擊密度當自變數，量測偵測率
#   如何隨密度變化，畫出「偵測率 vs 攻擊密度」曲線。這是合理的 sensitivity study。
#
# ⚠ 方法學鐵律（否則變灌水）：
#   PR-AUC 的 no-skill 基線 = 正例比例本身。密度一變，PR-AUC 會『自動』移動，
#   那不是偵測力的變化。因此本掃描的評估**主軸**必須是與基線無關的量：
#     - 逐秒 recall @ 固定零誤報閾值（thr = val 純正常分數 max）
#     - 逐秒 FP 數（絕對誤報，與密度無關）
#     - lift = PR-AUC ÷ 正例比例（把基線效應除掉）
#   **絕對不要**把不同密度的 PR-AUC 直接比大小當成「偵測變準/變差」。
#
# 做法：固定拓樸（單 sensor+單 motor，與 collect_v2.sh 同）、固定 BASELINE_SEC=300，
#   只改四種攻擊的注入次數（-DN_INJECT/-DN_FORGE/-DN_REPLAY/-DN_WRITES）。
#   每個密度點跑 REP 輪 Four_combined，場景名帶密度標籤便於後續分組評估。
#
# 密度定義：以「每 300s 注入的異常筆數」表示。DENSITIES 陣列即每種攻擊各注入幾筆。
#   單 pair 的 benign 約 300 秒 → 逐秒正例比例 ≈ (4×N) / 300。
#   例：N=5 → ~6.7%(秒級 4 類各 5 筆)... 實際比例採集後由 parse 統計，勿手算當準。
#
# 用法：
#   ./ml/collect_density_sweep.sh              # 預設密度點 {5,15,30,60,120}，每點 3 輪
#   ./ml/collect_density_sweep.sh "5 30 120" 2 # 自訂密度點與輪數
# =============================================================================
set -u

DENSITIES_STR="${1:-5 15 30 60 120}"    # 每種攻擊在 300s 內注入幾筆
REP="${2:-3}"                            # 每個密度點跑幾輪
read -r -a DENSITIES <<< "$DENSITIES_STR"
ATTACK_SEC=300

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
LOGROOT="$ROOT/attacks/logs"
REPORT="$LOGROOT/densitysweep_report_${STAMP}.txt"
BINDIR="$(mktemp -d)"                     # 各密度點的攻擊二進位放這（不污染 attacks/）

echo "[sweep] 編譯基礎程式 ..."
for p in aggregation_server sensor_pub Anomaly_client; do
  [ -x "$p" ] && [ ! "$p.c" -nt "$p" ] || gcc -o "$p" "$p.c" $UA_INC $UA_LIB || exit 1
done
HAVE_MOTOR=1
gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/dev/null || HAVE_MOTOR=0
[ "$HAVE_MOTOR" = "0" ] && { echo "[sweep] ✗ 需要 motor_sub（R 洩漏修正前提）"; exit 1; }

# 為某密度 N 編譯一組攻擊二進位（注入次數全設為 N）
build_attacks_for() {
  local N="$1" out="$2"
  gcc -DN_INJECT=$N -o "$out/spoof_attack"       attacks/spoof_attack.c       $UA_INC $UA_LIB 2>/dev/null || return 1
  gcc -DN_FORGE=$N  -o "$out/repudiation_attack" attacks/repudiation_attack.c $UA_INC $UA_LIB 2>/dev/null || return 1
  gcc -DN_REPLAY=$N -o "$out/replay_attack"      attacks/replay_attack.c      $UA_INC $UA_LIB 2>/dev/null || return 1
  gcc -DN_WRITES=$N -o "$out/tamper_attack"      attacks/tamper_attack.c      $UA_INC $UA_LIB 2>/dev/null || return 1
}

kill_all() {
  ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client|_attack' | grep -v grep \
    | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 2
}
PIDS=()
trap 'for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; kill_all; rm -rf "$BINDIR"; exit 130' INT TERM

start_system() {
  local dest="$1"; PIDS=()
  ./aggregation_server > "$dest/agg.log" 2>&1 & PIDS+=($!); sleep 3
  ./sensor_pub 1       > "$dest/sensor.log" 2>&1 & PIDS+=($!); sleep 1
  ./motor_sub 1 1      > "$dest/motor.log"  2>&1 & PIDS+=($!)
  ./Anomaly_client     > "$dest/anomaly.log" 2>&1 & PIDS+=($!); sleep 3
}
stop_system() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; sleep 2; kill_all; }

echo "" | tee "$REPORT"
echo "============================================================" | tee -a "$REPORT"
echo "【實驗2】攻擊密度掃描 ($STAMP)" | tee -a "$REPORT"
echo "  密度點(每300s注入筆數/類): ${DENSITIES[*]}  × 每點 ${REP} 輪" | tee -a "$REPORT"
echo "  ⚠ 評估用逐秒 recall@零誤報 與 lift，不可直接比 PR-AUC 絕對值" | tee -a "$REPORT"
echo "============================================================" | tee -a "$REPORT"
kill_all

# 一個共用的純 benign 場景（給所有密度點當同一份訓練/定閾值基準）
DEST="$LOGROOT/densitysweep_baseline_${STAMP}"; mkdir -p "$DEST"
echo "[sweep] === baseline（純正常, 10 分）給定閾值用 ==="
start_system "$DEST"; sleep 600; stop_system
echo "--- densitysweep_baseline: 行數=$(grep -c 'Anomaly Input' "$DEST/anomaly.log")" | tee -a "$REPORT"

for N in "${DENSITIES[@]}"; do
  echo "[sweep] === 密度 N=$N 編譯攻擊 ==="
  build_attacks_for "$N" "$BINDIR" || { echo "[sweep] ✗ N=$N 編譯失敗"; exit 1; }
  for r in $(seq 1 "$REP"); do
    DEST="$LOGROOT/densitysweep_d${N}_r${r}_${STAMP}"; mkdir -p "$DEST"
    echo "[sweep]   --- N=$N 輪 $r/$REP (${ATTACK_SEC}s) ---"
    start_system "$DEST"
    "$BINDIR/spoof_attack"       > "$DEST/spoof_attack.log"       2>&1 & A1=$!
    "$BINDIR/tamper_attack"      > "$DEST/tamper_attack.log"      2>&1 & A2=$!
    "$BINDIR/repudiation_attack" > "$DEST/repudiation_attack.log" 2>&1 & A3=$!
    "$BINDIR/replay_attack"      > "$DEST/replay_attack.log"      2>&1 & A4=$!
    sleep $(( ATTACK_SEC + 10 ))
    kill -9 $A1 $A2 $A3 $A4 2>/dev/null
    stop_system
    # ⚠ 必須產生 anomaly_marked.log，否則 parse_logs.py 會把該場景當全正常（教訓）。
    ml/venv/bin/python ml/mark_anomalies.py "$DEST" 2>/dev/null || python3 ml/mark_anomalies.py "$DEST"
    echo "--- densitysweep_d${N}_r${r}: 行數=$(grep -c 'Anomaly Input' "$DEST/anomaly.log") null=$(grep -c 'SourceNode=null' "$DEST/anomaly.log")" | tee -a "$REPORT"
  done
done

rm -rf "$BINDIR"
{
  echo ""
  echo "============================================================"
  echo "採集完成 —— 下一步"
  echo "============================================================"
  echo "  ml/venv/bin/python ml/parse_logs.py"
  echo "  ml/venv/bin/python ml/eval_density_sweep.py   # 產生密度-偵測率曲線"
  echo ""
  echo "  曲線的 x 軸=實測秒級正例比例(由 parse 統計)，y 軸建議三條："
  echo "    (a) 逐秒 recall @ 零誤報閾值   (b) 逐秒 FP 數   (c) lift=PR-AUC/正例比例"
} | tee -a "$REPORT"
echo "[sweep] 報告已存：$REPORT"
