#!/bin/bash
# =============================================================================
# collect_v2.sh ── 新格式（LogRecord + SourceNode）多輪採集
# =============================================================================
# 與 collect_sourcenode.sh 的差異：
#   1. 攻擊場景跑 **多輪**，把每類異常的樣本數拉高（舊實驗 R=4/T=10/RP=8 太少，
#      屬案例級佐證而非統計顯著 —— 這是舊報告自己列出的第一個已知限制）。
#   2. baseline 同步加長，維持異常佔比接近真實的 ~0.2%，而不是靠提高異常比例灌水。
#   3. motor_sub 本機現在可編譯 → 新資料含真 motor 下游行為（舊實驗缺這塊）。
#
# 用法：
#   ./ml/collect_v2.sh                    # 預設 baseline 60 分 + benign對照×2 + FC×10 + R×10
#   ./ml/collect_v2.sh 60 10 10 2         # baseline分鐘 FC輪數 R輪數 benign對照輪數
#
# 相對舊版的三個關鍵修正（對應 n-gram/DeepLog 分析揭露的資料集缺陷）：
#   [修1] R 洩漏已在 motor_sub.c 修掉（日誌與 GPIO 解耦）：benign 現在會自然出現
#         "Distance too close / safe" 模板，R 攻擊不再靠模板新穎性白送命中。
#         → 前提：本次採集必須實際啟動 motor_sub（HAVE_MOTOR=1）。
#   [修2] 新增 benign 對照場景：用與攻擊場景『完全相同』的 client 拓撲與時序，
#         只是不注入攻擊。這消除了「baseline 太乾淨、測試場景較雜」的分佈落差
#         （舊資料：baseline 同秒雙報 0 次，攻擊場景的正常行卻有 92 次）。
#   [修3] 攻擊輪數預設拉高（FC/R 各 10 輪），把每類異常樣本數從『案例級』提升到
#         可算 PR-AUC 誤差條的統計級（舊資料 seen-only 只剩 40 個正例）。
# =============================================================================
set -u

MINUTES="${1:-60}"
N_FC="${2:-10}"                   # Four_combined 輪數（舊預設 3 → 10）
N_R="${3:-10}"                    # R_only 輪數（舊預設 2 → 10）
N_BENIGN="${4:-2}"               # benign 對照輪數（同攻擊 harness、關注入）
ATTACK_SEC=300                    # 與攻擊原始碼的 BASELINE_SEC 一致

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
LOGROOT="$ROOT/attacks/logs"
REPORT="$LOGROOT/v2_collection_report_${STAMP}.txt"

# ---------------------------------------------------------------------------
# 0) 前置檢查
# ---------------------------------------------------------------------------
echo "[v2] === 前置檢查 ==="
for p in aggregation_server sensor_pub Anomaly_client; do
  if [ ! -x "$p" ] || [ "$p.c" -nt "$p" ]; then
    gcc -o "$p" "$p.c" $UA_INC $UA_LIB 2>/tmp/v2_build_$p.err \
      && echo "[v2]   ✓ 編譯 $p" \
      || { echo "[v2]   ✗ $p 編譯失敗："; sed -n '1,5p' /tmp/v2_build_$p.err; exit 1; }
  fi
done

HAVE_MOTOR=1
if [ ! -x motor_sub ] || [ motor_sub.c -nt motor_sub ]; then
  gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/dev/null \
    && echo "[v2]   ✓ 編譯 motor_sub" \
    || { HAVE_MOTOR=0; echo "[v2]   ⚠ motor_sub 無法編譯 → 本次不啟動 motor"; }
fi
[ "$HAVE_MOTOR" = "1" ] && echo "[v2] ✓ motor_sub 可用（舊實驗缺此下游節點）"

if ! grep -q "SourceNode=" aggregation_server 2>/dev/null; then
  echo "[v2] ✗ aggregation_server 不含 SourceNode 蓋章邏輯，請確認為新版原始碼。"; exit 1
fi
echo "[v2] ✓ aggregation_server 含 SourceNode 蓋章邏輯"

for a in repudiation_attack spoof_attack tamper_attack replay_attack; do
  gcc -o "attacks/$a" "attacks/$a.c" $UA_INC $UA_LIB 2>/dev/null \
    && echo "[v2]   ✓ $a" || { echo "[v2]   ✗ $a 編譯失敗"; exit 1; }
done

kill_all() {
  ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client|_attack' | grep -v grep \
    | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 2
}

PIDS=()
cleanup_trap() {
  echo ""; echo "[v2] 中斷，收尾中..."
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  kill_all; exit 130
}
trap cleanup_trap INT TERM

# ---------------------------------------------------------------------------
# ground truth 標記（邏輯與 collect_sourcenode.sh 完全一致，避免兩份標準）
# ---------------------------------------------------------------------------
make_marked() {
  local dest="$1" scen="$2"
  python3 - "$dest" "$scen" <<'PYEOF'
import sys, os, re
dest, scen = sys.argv[1], sys.argv[2]
anom = os.path.join(dest, "anomaly.log")
if not os.path.exists(anom):
    sys.exit(0)

lines = open(anom, encoding="utf-8", errors="replace").read().splitlines()

DESC = {"R": "Repudiation 否認：冒充他人(motor)寫入、事後無法歸屬的偽造操作 log",
        "S": "Spoofing 欺騙：偽造的 sensor 距離（同一秒出現雙報）",
        "T": "Tampering 竄改：對唯讀節點寫入，被拒 BadUserAccessDenied",
        "RP": "Replay 重放：內容(含原始時間戳)與過去事件完全相同、被重送的重複行"}

def classify(msg, seen_before):
    if "BadUserAccessDenied" in msg:
        return "T"
    if "[Motor]" in msg and ("rotating motor" in msg or "Distance too close" in msg
                             or "Distance safe" in msg):
        return "R"
    if "[Sensor]" in msg and "Updated distance" in msg:
        return "RP" if seen_before else "S"
    return None

def core(s):
    s = s.replace("[Anomaly Input] ", "", 1)
    s = re.split(r'\s*\|\s*SourceNode=', s)[0]
    return re.sub(r'\s+', ' ', s).strip()

out, n_marked, seen = [], {}, set()
for raw in lines:
    if "[Anomaly Input]" in raw:
        body = core(raw)
        at = None
        if "SourceNode=null" in raw:
            at = classify(body, body in seen) or "R"
        elif "BadUserAccessDenied" in raw:
            at = "T"
        if at:
            n_marked[at] = n_marked.get(at, 0) + 1
            out.append(f">>> {raw}   # ⚠ [{at}] {DESC[at]}")
            seen.add(body); continue
        seen.add(body)
    out.append(raw)

hdr = ["# " + "=" * 76,
       f"# anomaly.log 異常標記版  —  場景：{scen}",
       "# 行首 '>>>' = 異常。行尾 '# ⚠ [類別] 說明'。"]
for a in ["S", "T", "R", "RP"]:
    if a in n_marked:
        hdr.append(f"#   [{a}] = {DESC[a]}")
hdr += ["# grep： grep '^>>>' anomaly_marked.log ；grep '\\[R\\]'",
        "# " + "=" * 76, ""]

with open(os.path.join(dest, "anomaly_marked.log"), "w", encoding="utf-8") as f:
    f.write("\n".join(hdr + out) + "\n")
print("      標記結果：" + (", ".join(f"{k}={v}" for k, v in sorted(n_marked.items())) or "無"))
PYEOF
}

start_system() {
  local dest="$1"
  PIDS=()
  ./aggregation_server > "$dest/agg.log"     2>&1 & PIDS+=($!)
  sleep 2
  ./sensor_pub         > "$dest/sensor.log"  2>&1 & PIDS+=($!)
  [ "$HAVE_MOTOR" = "1" ] && { ./motor_sub > "$dest/motor.log" 2>&1 & PIDS+=($!); }
  ./Anomaly_client     > "$dest/anomaly.log" 2>&1 & PIDS+=($!)
  sleep 3
}

stop_system() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  sleep 2; kill_all
}

report_scenario() {
  local dest="$1" scen="$2"
  local n_total n_verified n_null
  n_total=$(grep -c "Anomaly Input" "$dest/anomaly.log" 2>/dev/null || echo 0)
  n_verified=$(grep -c "SourceNode=ns=1;s=" "$dest/anomaly.log" 2>/dev/null || echo 0)
  n_null=$(grep -c "SourceNode=null" "$dest/anomaly.log" 2>/dev/null || echo 0)
  {
    echo "--- $scen"
    echo "    總行數           : $n_total"
    echo "    SourceNode 已驗證: $n_verified"
    echo "    SourceNode = null: $n_null   ← 匿名寫入（攻擊者落在這裡）"
  } | tee -a "$REPORT"
}

echo "" | tee "$REPORT"
echo "============================================================" | tee -a "$REPORT"
echo "新格式 log 多輪採集報告 v2  ($STAMP)" | tee -a "$REPORT"
echo "  baseline ${MINUTES} 分 · benign對照 ×${N_BENIGN} · Four_combined ×${N_FC} · R_only ×${N_R}" | tee -a "$REPORT"
echo "============================================================" | tee -a "$REPORT"
if [ "$HAVE_MOTOR" = "0" ]; then
  echo "⚠ 嚴重：motor_sub 未啟動 → benign 不會有 'Distance too close/safe' 模板，" | tee -a "$REPORT"
  echo "  R 洩漏修正 [修1] 無法生效，本次採集的 R 偵測結果仍不可引用。" | tee -a "$REPORT"
  echo "  請先讓 motor_sub 編得起來（gcc ... -llgpio）再採集。" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

kill_all

# ---------------------------------------------------------------------------
# 1) 純正常 baseline
# ---------------------------------------------------------------------------
DEST="$LOGROOT/v2_baseline_${MINUTES}min_${STAMP}"
mkdir -p "$DEST"
echo "[v2] === (1) 純正常 baseline：${MINUTES} 分鐘 ==="
start_system "$DEST"
elapsed=0; DUR=$(( MINUTES * 60 ))
while [ "$elapsed" -lt "$DUR" ]; do
  sleep 60; elapsed=$(( elapsed + 60 ))
  n=$(grep -c "Anomaly Input" "$DEST/anomaly.log" 2>/dev/null || echo 0)
  echo "[v2]     ${elapsed}s / ${DUR}s，已收集 $n 行"
done
stop_system
make_marked "$DEST" "$(basename "$DEST")"
report_scenario "$DEST" "$(basename "$DEST")"
echo ""

# ---------------------------------------------------------------------------
# 1b) benign 對照 × N：與攻擊場景同 harness、同時長，但不注入任何攻擊
# ---------------------------------------------------------------------------
# 目的：攻擊場景的「正常行」分佈，必須有一組不含攻擊、卻用相同 client 拓撲與
#       ATTACK_SEC 時長跑出來的對照。這樣訓練/評估看到的 benign 世界才一致，
#       誤報率才不是被「baseline 比測試場景乾淨」這個假象撐出來的。
# 命名：必須以 'v2_baseline' 開頭 —— ngram_detector.py / compare 用 startswith
#       ("v2_baseline") 選訓練集，這樣 harness-matched benign 才會併入訓練集，
#       正是修正「訓練集太乾淨」的關鍵；獨立場景名便於單獨 sanity check。
for i in $(seq 1 "$N_BENIGN"); do
  DEST="$LOGROOT/v2_baseline_ctrl_r${i}_${STAMP}"
  mkdir -p "$DEST"
  echo "[v2] === (1b.$i/$N_BENIGN) benign 對照：同攻擊 harness、關注入（${ATTACK_SEC}s）==="
  start_system "$DEST"
  # 不啟動任何 ./attacks/*，其餘與 Four_combined 完全一致。
  sleep $(( ATTACK_SEC + 10 ))
  stop_system
  make_marked "$DEST" "$(basename "$DEST")"
  # benign 對照理論上不該有任何 SourceNode=null；report 會把它列出來供 sanity check。
  report_scenario "$DEST" "$(basename "$DEST")"
  echo ""
done

# ---------------------------------------------------------------------------
# 2) Four_combined × N：S+T+R+RP 並存（最真實場景）
# ---------------------------------------------------------------------------
for i in $(seq 1 "$N_FC"); do
  DEST="$LOGROOT/v2_Four_combined_r${i}_${STAMP}"
  mkdir -p "$DEST"
  echo "[v2] === (2.$i/$N_FC) Four_combined：S+T+R+RP（${ATTACK_SEC}s）==="
  start_system "$DEST"
  ./attacks/spoof_attack       > "$DEST/spoof_attack.log"       2>&1 & A1=$!
  ./attacks/tamper_attack      > "$DEST/tamper_attack.log"      2>&1 & A2=$!
  ./attacks/repudiation_attack > "$DEST/repudiation_attack.log" 2>&1 & A3=$!
  ./attacks/replay_attack      > "$DEST/replay_attack.log"      2>&1 & A4=$!
  sleep $(( ATTACK_SEC + 10 ))
  kill -9 $A1 $A2 $A3 $A4 2>/dev/null
  stop_system
  make_marked "$DEST" "$(basename "$DEST")"
  report_scenario "$DEST" "$(basename "$DEST")"
  echo ""
done

# ---------------------------------------------------------------------------
# 3) R_only × N：否認攻擊單獨場景
# ---------------------------------------------------------------------------
for i in $(seq 1 "$N_R"); do
  DEST="$LOGROOT/v2_R_only_r${i}_${STAMP}"
  mkdir -p "$DEST"
  echo "[v2] === (3.$i/$N_R) R_only：否認攻擊（${ATTACK_SEC}s）==="
  start_system "$DEST"
  ./attacks/repudiation_attack > "$DEST/repudiation_attack.log" 2>&1 & ATK=$!
  sleep $(( ATTACK_SEC + 10 ))
  kill -9 $ATK 2>/dev/null
  stop_system
  make_marked "$DEST" "$(basename "$DEST")"
  report_scenario "$DEST" "$(basename "$DEST")"
  echo ""
done

{
  echo ""
  echo "============================================================"
  echo "採集完成 —— 下一步"
  echo "============================================================"
  echo "  ml/venv/bin/python ml/parse_logs.py            # 重建 parsed_all.csv"
  echo "  ml/venv/bin/python ml/ngram_detector.py        # n-gram/bigram"
  echo "  ml/venv/bin/python ml/compare_ngram_deeplog.py # vs DeepLog"
  echo ""
  echo "驗收指標（這批修正是否生效）："
  echo "  1. benign(baseline) 場景應出現 'Distance too close/safe' 模板 → R 洩漏已修"
  echo "  2. ngram_detector 的 (A)全量 與 (B)seen-only PR-AUC 應收斂 → 不再靠新模板"
  echo "  3. v2_baseline_ctrl_* 的 SourceNode=null 應為 0 → benign 對照乾淨"
} | tee -a "$REPORT"
echo "[v2] 報告已存：$REPORT"
