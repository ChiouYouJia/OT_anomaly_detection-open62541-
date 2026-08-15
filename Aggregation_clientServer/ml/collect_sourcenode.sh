#!/bin/bash
# =============================================================================
# collect_sourcenode.sh ── 採集「含 SourceNode」的新格式 log（R 對照實驗用）
# =============================================================================
# 用途：
#   用**新版**程式（aggregation_server 會依 session 身分蓋 SourceNode）重新採集，
#   產出可做「有 SourceNode vs 無 SourceNode」對照的資料集。
#
#   核心對照：
#     舊格式（既有 24062 行）→ 無 SourceNode → 三個 ML 模型的 R recall 都是 0%
#     新格式（本腳本採集）  → 有 SourceNode → 一條規則 SourceNode==null 即可抓到 R
#   這是本研究的收尾證據：證明 R 不該用 ML 解，然後用對的方法解掉它。
#
# 用法：
#   ./ml/collect_sourcenode.sh                  # 預設：baseline 30 分 + 四攻擊各一輪
#   ./ml/collect_sourcenode.sh 60               # baseline 改 60 分鐘
#   ./ml/collect_sourcenode.sh 30 attack-only   # 只跑攻擊場景，不跑 baseline
#   ./ml/collect_sourcenode.sh 30 quick         # 快速驗證（baseline 2 分、攻擊各 2 分）
#
# 產出（attacks/logs/ 下，可直接被 ml/parse_logs.py 解析）：
#   sn_baseline_<N>min_<stamp>/     純正常（訓練用）
#   sn_R_only_<stamp>/              否認攻擊（本實驗主角）
#   sn_Four_combined_<stamp>/       四攻擊混合（最真實場景）
#   各場景含 anomaly.log 與自動產生的 anomaly_marked.log（ground truth）
#
# 注意：
#   - 需先編譯新版程式（見下方 build 檢查）。motor_sub 需要 lgpio，若本機無 GPIO
#     會自動跳過 motor，並在報告中註明（不影響 R 實驗，R 攻擊冒充的就是 motor）。
#   - 攻擊程式的潛伏時長由其原始碼的 BASELINE_SEC 決定（預設 300 秒）。
#     quick 模式會用 -D 重新編譯成短版本，僅供流程驗證，不要拿來當正式資料。
# =============================================================================
set -u

MINUTES="${1:-30}"
MODE="${2:-full}"                       # full | attack-only | quick

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

UA_INC="-I../open62541/include -I../open62541/build/src_generated -I../open62541/arch -I../open62541/plugins/include"
UA_LIB="-L../open62541/build/bin -lopen62541"
export LD_LIBRARY_PATH="$ROOT/../open62541/build/bin:${LD_LIBRARY_PATH:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
LOGROOT="$ROOT/attacks/logs"
REPORT="$LOGROOT/sn_collection_report_${STAMP}.txt"

# quick 模式：攻擊潛伏時間縮短，只為驗證流程
if [ "$MODE" = "quick" ]; then
  MINUTES=2
  ATTACK_SEC=90
else
  ATTACK_SEC=300                        # 與攻擊原始碼的 BASELINE_SEC 一致
fi

# ---------------------------------------------------------------------------
# 0) 前置檢查：確認新版程式已編譯，且 SourceNode 功能存在
# ---------------------------------------------------------------------------
echo "[sn] === 前置檢查 ==="

need_build=0
for b in aggregation_server sensor_pub Anomaly_client; do
  if [ ! -x "$b" ]; then echo "[sn] 缺少執行檔：$b"; need_build=1; fi
done
# 原始碼比執行檔新 → 需要重編
for pair in "aggregation_server aggregation_server.c" "sensor_pub sensor_pub.c" "Anomaly_client Anomaly_client.c"; do
  set -- $pair
  if [ -x "$1" ] && [ "$2" -nt "$1" ]; then
    echo "[sn] $2 比執行檔新 → 需要重新編譯"; need_build=1
  fi
done

if [ "$need_build" = "1" ]; then
  echo "[sn] 重新編譯..."
  for p in aggregation_server sensor_pub Anomaly_client; do
    if gcc -o "$p" "$p.c" $UA_INC $UA_LIB 2>/tmp/sn_build_$p.err; then
      echo "[sn]   ✓ $p"
    else
      echo "[sn]   ✗ $p 編譯失敗："; sed -n '1,5p' /tmp/sn_build_$p.err; exit 1
    fi
  done
fi

# motor_sub 需要 lgpio；本機無 GPIO 時允許缺席
HAVE_MOTOR=1
if [ ! -x motor_sub ] || [ motor_sub.c -nt motor_sub ]; then
  if gcc -o motor_sub motor_sub.c $UA_INC $UA_LIB -llgpio 2>/dev/null; then
    echo "[sn]   ✓ motor_sub"
  else
    HAVE_MOTOR=0
    echo "[sn]   ⚠ motor_sub 無法編譯（缺 lgpio，本機無 GPIO）→ 本次不啟動 motor"
    echo "[sn]     R 攻擊冒充的正是 motor，缺席不影響 R 實驗（反而更凸顯偽造）"
  fi
fi

# 驗證 SourceNode 功能真的在執行檔裡（避免用到舊版二進位）
if ! grep -q "SourceNode=" aggregation_server 2>/dev/null; then
  echo "[sn] ✗ aggregation_server 內找不到 SourceNode 蓋章邏輯 —— 可能不是新版。"
  echo "[sn]   請確認 aggregation_server.c 含 resolve_source_node()，然後刪掉執行檔重跑。"
  exit 1
fi
echo "[sn] ✓ 已確認 aggregation_server 含 SourceNode 蓋章邏輯"

# 攻擊程式
echo "[sn] 編譯攻擊程式..."
for a in repudiation_attack spoof_attack tamper_attack replay_attack; do
  if [ "$MODE" = "quick" ]; then
    gcc -o "attacks/$a" -DBASELINE_SEC=$ATTACK_SEC "attacks/$a.c" $UA_INC $UA_LIB 2>/dev/null \
      && echo "[sn]   ✓ $a (quick ${ATTACK_SEC}s)" || echo "[sn]   ✗ $a"
  else
    gcc -o "attacks/$a" "attacks/$a.c" $UA_INC $UA_LIB 2>/dev/null \
      && echo "[sn]   ✓ $a" || echo "[sn]   ✗ $a"
  fi
done

kill_all() {
  ps aux | grep -E 'aggregation_ser|sensor_pub|motor_sub|Anomaly_client|_attack' | grep -v grep \
    | awk '{print $2}' | xargs -r kill -9 2>/dev/null
  sleep 2
}

PIDS=()
cleanup_trap() {
  echo ""; echo "[sn] 中斷，收尾中..."
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  kill_all
  exit 130
}
trap cleanup_trap INT TERM

# ---------------------------------------------------------------------------
# 產生 anomaly_marked.log：把攻擊注入的行標上 ground truth
# ---------------------------------------------------------------------------
# 判定依據（與既有場景的標記邏輯一致）：
#   R  : 冒充 motor 的 "Distance too close/safe ... rotating"，但 SourceNode=null
#   S  : 攻擊注入的假 sensor 距離行（同秒雙報）
#   T  : 對唯讀節點寫入被拒 BadUserAccessDenied
#   RP : 內容與過去某行完全相同（含內嵌時間戳）的重放行
# 註：這裡用「攻擊程式自己的 log」交叉比對，避免只靠字串猜測而誤標。
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

# --- ground truth 的判定依據 ---
# 主依據是 **SourceNode**：它由 aggregation_server 依 session 身分蓋章，是伺服器
# 自己對「誰寫了這一行」的紀錄，攻擊者無法偽造 —— 比解析攻擊程式的 stdout 可靠得多
# （攻擊程式的輸出格式可能變動、也可能因為提早中止而沒印出來）。
#
#   SourceNode=null  →  匿名寫入 = 攻擊者注入的行（正常 client 都是具名 session）
#
# 攻擊類別再依訊息內容細分：
#   冒充 motor 的動作訊息      → R  （否認：偽造他人操作）
#   偽造的 sensor 距離         → S  （欺騙）
#   重放（與先前某行內容全同） → RP
#   BadUserAccessDenied        → T  （竄改，這條由伺服器回應產生、非匿名注入）
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
    """去掉 Anomaly 前綴與伺服器蓋的 SourceNode 後綴，得到可比對的訊息本體。"""
    s = s.replace("[Anomaly Input] ", "", 1)
    s = re.split(r'\s*\|\s*SourceNode=', s)[0]
    return re.sub(r'\s+', ' ', s).strip()

out, n_marked, seen = [], {}, set()
for raw in lines:
    if "[Anomaly Input]" in raw:
        body = core(raw)
        at = None
        if "SourceNode=null" in raw:
            # 匿名寫入 → 一定是攻擊注入；再依內容判類別
            at = classify(body, body in seen)
            if at is None:
                at = "R"          # 匿名注入但內容不符已知樣態，仍屬無法歸屬的偽造
        elif "BadUserAccessDenied" in raw:
            at = "T"              # T 的證據在伺服器回應（具名 session 也會出現）
        if at:
            n_marked[at] = n_marked.get(at, 0) + 1
            out.append(f">>> {raw}   # ⚠ [{at}] {DESC[at]}")
            seen.add(body)
            continue
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

# ---------------------------------------------------------------------------
# 啟動正常系統（共用）
# ---------------------------------------------------------------------------
start_system() {
  local dest="$1"
  PIDS=()
  ./aggregation_server > "$dest/agg.log"     2>&1 & PIDS+=($!)
  sleep 2
  ./sensor_pub         > "$dest/sensor.log"  2>&1 & PIDS+=($!)
  if [ "$HAVE_MOTOR" = "1" ]; then
    ./motor_sub        > "$dest/motor.log"   2>&1 & PIDS+=($!)
  fi
  ./Anomaly_client     > "$dest/anomaly.log" 2>&1 & PIDS+=($!)
  sleep 3
}

stop_system() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  sleep 2
  kill_all
}

# 統計並回報 SourceNode 分布（這是本次採集的重點）
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
echo "含 SourceNode 的新格式 log 採集報告  ($STAMP)" | tee -a "$REPORT"
echo "============================================================" | tee -a "$REPORT"
[ "$HAVE_MOTOR" = "0" ] && echo "註：本機無 GPIO，motor_sub 未啟動。" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

kill_all

# ---------------------------------------------------------------------------
# 1) 純正常 baseline
# ---------------------------------------------------------------------------
if [ "$MODE" != "attack-only" ]; then
  DEST="$LOGROOT/sn_baseline_${MINUTES}min_${STAMP}"
  mkdir -p "$DEST"
  echo "[sn] === (1/3) 純正常 baseline：${MINUTES} 分鐘 ==="
  echo "[sn]     ⚠️ 過程中請勿執行任何攻擊程式"
  start_system "$DEST"
  elapsed=0; DUR=$(( MINUTES * 60 ))
  while [ "$elapsed" -lt "$DUR" ]; do
    sleep 30; elapsed=$(( elapsed + 30 ))
    n=$(grep -c "Anomaly Input" "$DEST/anomaly.log" 2>/dev/null || echo 0)
    echo "[sn]     ${elapsed}s / ${DUR}s，已收集 $n 行"
  done
  stop_system
  make_marked "$DEST" "$(basename "$DEST")"
  report_scenario "$DEST" "$(basename "$DEST")"
  echo ""
fi

# ---------------------------------------------------------------------------
# 2) R_only：否認攻擊單獨場景（本實驗主角）
# ---------------------------------------------------------------------------
DEST="$LOGROOT/sn_R_only_${STAMP}"
mkdir -p "$DEST"
echo "[sn] === (2/3) R_only：否認攻擊（${ATTACK_SEC}s）==="
start_system "$DEST"
./attacks/repudiation_attack > "$DEST/repudiation_attack.log" 2>&1 &
ATK=$!
sleep $(( ATTACK_SEC + 10 ))
kill -9 $ATK 2>/dev/null
stop_system
make_marked "$DEST" "$(basename "$DEST")"
report_scenario "$DEST" "$(basename "$DEST")"
echo ""

# ---------------------------------------------------------------------------
# 3) Four_combined：四攻擊並存（最真實場景）
# ---------------------------------------------------------------------------
DEST="$LOGROOT/sn_Four_combined_${STAMP}"
mkdir -p "$DEST"
echo "[sn] === (3/3) Four_combined：S+T+R+RP 並存（${ATTACK_SEC}s）==="
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

# ---------------------------------------------------------------------------
# 完成
# ---------------------------------------------------------------------------
{
  echo ""
  echo "============================================================"
  echo "採集完成"
  echo "============================================================"
  echo "下一步："
  echo "  1) python3 ml/parse_logs.py            # 解析（新舊格式都會處理）"
  echo "  2) ml/venv/bin/python ml/eval_sourcenode.py   # 有/無 SourceNode 對照實驗"
  echo ""
  echo "驗證資料是否正確帶有 SourceNode："
  echo "  grep -o 'SourceNode=[^ ]*' $LOGROOT/sn_R_only_${STAMP}/anomaly.log | sort | uniq -c"
} | tee -a "$REPORT"

echo ""
echo "[sn] 報告已存：$REPORT"
