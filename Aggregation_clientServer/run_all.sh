#!/bin/bash
# =============================================================================
# run_all.sh ── 啟動全部節點（1 sensor + 3 motor + 彙整伺服器 + 監看 client）
# =============================================================================
# 拓撲：
#        sensor_pub (OPC UA server @4842)
#          ▲        ▲        ▲              ← 3 台 motor 訂閱同一個 sensor
#       motor1   motor2   motor3            （各綁 127.0.0.2/.3/.4）
#          │        │        │
#          └────────┼────────┘  各自把 log 寫進 ▼
#                   ▼
#        aggregation_server (OPC UA server @4840)
#                   ▲
#            Anomaly_client（讀取彙整後的 log）
#
# 用法：
#   ./run_all.sh              # 啟動並即時顯示彙整 log（Ctrl-C 停止全部）
#   ./run_all.sh -q           # 只啟動，不跟 log（背景執行）
#   ./run_all.sh -n 5         # 改成 5 台 motor
#
# log 位置： logs/run_<時間戳>/
#   anomaly.log   ← 彙整伺服器收到的所有 log（最有價值，含 SourceNode）
#   agg.log       ← 彙整伺服器自身
#   sensor.log    ← sensor
#   motor1~N.log  ← 各台 motor
# =============================================================================
set -u

N_MOTOR=3
FOLLOW=1
while [ $# -gt 0 ]; do
  case "$1" in
    -n) N_MOTOR="$2"; shift 2 ;;
    -q) FOLLOW=0; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "未知參數：$1（-h 看說明）"; exit 1 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
DEST="$ROOT/logs/run_${STAMP}"
mkdir -p "$DEST"

# ---------------------------------------------------------------------------
# 1) 需要時才重編（原始碼比執行檔新）
# ---------------------------------------------------------------------------
for p in aggregation_server sensor_pub Anomaly_client; do
  if [ ! -x "$p" ] || [ "$p.c" -nt "$p" ]; then
    echo "[run] 編譯 $p ..."
    gcc -o "$p" "$p.c" $UA_INC $UA_LIB || { echo "[run] ✗ $p 編譯失敗"; exit 1; }
  fi
done
if [ ! -x motor_sub ] || [ motor_sub.c -nt motor_sub ]; then
  echo "[run] 編譯 motor_sub ..."
  gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio || { echo "[run] ✗ motor_sub 編譯失敗"; exit 1; }
fi
# 來源 IP 綁定（讓每台 motor 在網路層可分；詳見 net/bindsrc.c）
if [ ! -f net/bindsrc.so ] || [ net/bindsrc.c -nt net/bindsrc.so ]; then
  gcc -shared -fPIC -o net/bindsrc.so net/bindsrc.c -ldl 2>/dev/null
fi

# ---------------------------------------------------------------------------
# 2) 清掉可能殘留的舊行程（避免埠口被占用）
# ---------------------------------------------------------------------------
ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client|_attack' \
  | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null
sleep 1

PIDS=()
cleanup() {
  echo ""
  echo "[run] 停止所有節點 ..."
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client' \
    | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  echo "[run] log 保留在：$DEST"
  exit 0
}
trap cleanup INT TERM

# ---------------------------------------------------------------------------
# 3) 依序啟動（順序有意義：server 要先就緒，client 才連得上）
# ---------------------------------------------------------------------------
echo "[run] 啟動 aggregation_server (@4840) ..."
./aggregation_server > "$DEST/agg.log" 2>&1 & PIDS+=($!)
sleep 2

echo "[run] 啟動 sensor_pub (@4842) ..."
./sensor_pub > "$DEST/sensor.log" 2>&1 & PIDS+=($!)
sleep 1

for i in $(seq 1 "$N_MOTOR"); do
  ip="127.0.0.$((i+1))"
  echo "[run] 啟動 motor_sub $i  (來源 IP $ip) ..."
  BIND_SRC="$ip" LD_PRELOAD="$ROOT/net/bindsrc.so" \
    ./motor_sub "$i" > "$DEST/motor${i}.log" 2>&1 & PIDS+=($!)
done

echo "[run] 啟動 Anomaly_client（讀取彙整 log）..."
./Anomaly_client > "$DEST/anomaly.log" 2>&1 & PIDS+=($!)
sleep 4

# ---------------------------------------------------------------------------
# 4) 確認真的都活著
# ---------------------------------------------------------------------------
alive=0
for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null && alive=$((alive+1)); done
total=$(( 3 + N_MOTOR ))
echo ""
echo "============================================================"
echo "  節點狀態： $alive / $total 個行程存活"
echo "  log 目錄： $DEST"
echo "============================================================"
if [ "$alive" -lt "$total" ]; then
  echo "  ⚠ 有行程未啟動成功，請看上面的 log 檔找原因"
fi

# 顯示各來源的 SourceNode（驗證三台 motor 真的分得開）
echo ""
echo "各來源寫入狀況（等 5 秒收集）..."
sleep 5
grep -o 'SourceNode=[^ ]*' "$DEST/anomaly.log" 2>/dev/null | sort | uniq -c | sed 's/^/   /'

echo ""
if [ "$FOLLOW" = "1" ]; then
  echo "============================================================"
  echo "  即時 log（Ctrl-C 停止全部節點）"
  echo "============================================================"
  tail -f "$DEST/anomaly.log"
else
  echo "已在背景執行。看 log："
  echo "   tail -f $DEST/anomaly.log"
  echo "停止全部："
  echo "   pkill -9 -f 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client'"
fi
