#!/usr/bin/env bash
# =============================================================================
# 階段 A — TCP connect-drop 洪水（連上即斷，衝擊 accept 迴圈）
#
# 一鍵完成：起系統 → 抓包 → baseline → 漸進三檔攻擊（輕→中→重）→ 收尾
# 產物：A_<時間戳>_{agg,sensor,motor,anomaly}.log  +  A_<時間戳>.pcap
#
# 一次跑完三檔流量，每檔之間插入恢復空檔，全部寫進同一組時間戳檔名。
#
# 用法：
#   ./run_dos_A.sh                 # 預設輕→中→重三檔
#   RUN_MOTOR=0 ./run_dos_A.sh     # 無 GPIO 時略過 motor_sub
#   BASELINE=30 RECOVER=10 ./run_dos_A.sh   # 縮短 baseline / 恢復空檔
# =============================================================================
cd "$(dirname "$0")"
PORT="${PORT:-4842}"

# 輕 / 中 / 重（conns rate dur）
STEPS=$(cat <<EOF
A --conns 5  --rate 5  --dur 15 --port $PORT
A --conns 20 --rate 20 --dur 15 --port $PORT
A --conns 50 --rate 50 --dur 20 --port $PORT
EOF
)

PHASE=A PORT="$PORT" ATTACK_STEPS="$STEPS" ./dos_runner.sh
