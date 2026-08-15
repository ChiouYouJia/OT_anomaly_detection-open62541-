#!/bin/bash
# =============================================================================
# collect_baseline.sh ── 產生「純正常」baseline log（無任何攻擊）
# =============================================================================
# 用途：啟動系統四支正常程式，跑指定時長，把 Anomaly_client 收集到的乾淨 log
#       存到 attacks/logs/baseline_<時長>_<時間戳>/。這批純正常資料供 ML 訓練
#       （DeepLog / autoencoder 都需要大量無異常的正常序列）。
#
# 用法：
#   ./ml/collect_baseline.sh [分鐘數]
#   例：
#     ./ml/collect_baseline.sh 60      # 跑 60 分鐘（預設）
#     ./ml/collect_baseline.sh 180     # 跑 3 小時
#
# 說明：
#   - sensor 每秒約 1 筆距離、motor 每秒約 1 筆，60 分鐘 ≈ 7000+ 行正常 log。
#   - 過程中請「不要」執行 attacks/ 下任何程式，否則就不純了。
#   - 要提早停止：按 Ctrl-C，腳本會收乾淨並保留已收集的 log。
#   - 跑完後 log 在 attacks/logs/baseline_.../anomaly.log，可直接餵 ml/parse_logs.py。
# =============================================================================
set -u

MINUTES="${1:-60}"                       # 預設 60 分鐘
DUR=$(( MINUTES * 60 ))

# 以此腳本位置定位專案根目錄（ml/ 的上一層）
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

STAMP="$(date +%Y%m%d_%H%M%S)"
DEST="$ROOT/attacks/logs/baseline_${MINUTES}min_${STAMP}"
mkdir -p "$DEST"

# 保險：先用 PID 精準清掉任何殘留（pkill -f aggregation_server 會因 15 字元截斷失效）
ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client|_attack' | grep -v grep \
  | awk '{print $2}' | xargs -r kill -9 2>/dev/null
sleep 2

PIDS=()
cleanup() {
  echo ""
  echo "[baseline] 收尾中，停止所有程式..."
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  sleep 2
  # 統計
  local n_total n_sensor n_motor
  n_total=$(grep -c "Anomaly Input" "$DEST/anomaly.log" 2>/dev/null || echo 0)
  n_sensor=$(grep -c "Sensor.*Updated distance" "$DEST/anomaly.log" 2>/dev/null || echo 0)
  n_motor=$(grep -c "Motor.*Received distance\|Motor.*Distance" "$DEST/anomaly.log" 2>/dev/null || echo 0)
  echo "[baseline] 完成。"
  echo "[baseline] 輸出資料夾: $DEST"
  echo "[baseline] Anomaly 收集總行數: $n_total  (sensor 距離 $n_sensor, motor $n_motor)"
  echo "[baseline] 下一步： python3 ml/parse_logs.py  會自動把它一起解析。"
  exit 0
}
trap cleanup INT TERM

echo "[baseline] 啟動系統，將跑 ${MINUTES} 分鐘（${DUR} 秒）。要提早停止按 Ctrl-C。"
echo "[baseline] ⚠️ 過程中請勿執行任何 attacks/ 程式，以保持 baseline 純淨。"

./aggregation_server > "$DEST/agg.log"     2>&1 & PIDS+=($!)
sleep 1
./sensor_pub         > "$DEST/sensor.log"  2>&1 & PIDS+=($!)
./motor_sub          > "$DEST/motor.log"   2>&1 & PIDS+=($!)
./Anomaly_client     > "$DEST/anomaly.log" 2>&1 & PIDS+=($!)

# 每 60 秒回報一次進度
elapsed=0
while [ "$elapsed" -lt "$DUR" ]; do
  sleep 60
  elapsed=$(( elapsed + 60 ))
  n=$(grep -c "Anomaly Input" "$DEST/anomaly.log" 2>/dev/null || echo 0)
  echo "[baseline] 已跑 $(( elapsed / 60 )) / ${MINUTES} 分鐘，目前收集 $n 行..."
done

cleanup
