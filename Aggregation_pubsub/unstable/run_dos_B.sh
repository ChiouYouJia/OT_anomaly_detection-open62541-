#!/usr/bin/env bash
# =============================================================================
# 階段 B — 半開連線佔槽（connect 後不送資料、也不關，佔住連線/channel 槽）
#
# 一鍵完成：起系統 → 抓包 → baseline → 漸進三檔攻擊（輕→中→重）→ 收尾
# 產物：B_<時間戳>_{agg,sensor,motor,anomaly}.log  +  B_<時間戳>.pcap
#
# 一次跑完三檔（占 20 → 50 → 100 條半開連線），每檔之間插入恢復空檔。
# 觀察重點：合法新連線是否被拒（BadTooManySecureChannels）、AggregatedDistance 是否停更
#
# 用法：
#   ./run_dos_B.sh                 # 預設輕→中→重三檔
#   RUN_MOTOR=0 ./run_dos_B.sh
#   BASELINE=30 RECOVER=10 ./run_dos_B.sh
# =============================================================================
cd "$(dirname "$0")"
PORT="${PORT:-4842}"

# 輕 / 中 / 重（同時持有的半開連線數 conns，dur=持續秒數）
STEPS=$(cat <<EOF
B --conns 20  --dur 30 --port $PORT
B --conns 50  --dur 30 --port $PORT
B --conns 100 --dur 40 --port $PORT
EOF
)

PHASE=B PORT="$PORT" ATTACK_STEPS="$STEPS" ./dos_runner.sh
