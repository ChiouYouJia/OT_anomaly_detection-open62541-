# OPC UA Log 異常檢測 — ML/NLP 管線

針對 `attacks/logs/` 產生的攻擊 log，做 log 異常檢測的專題管線。
STRIDE 攻擊：S(欺騙) / T(竄改) / R(否認) / RP(重放)。

> 本檔說明**方法與如何重現**。
>
> ⚠️ **本 repo 只收程式碼。** 實驗報告、論文草稿、量測數字、pcap、log、
> 圖檔一律不進版控（見根目錄 `.gitignore`）—— 每個人跑出來的數字取決於自己
> 採集的資料，照著〈[重現](#重現)〉跑一次就會在 `ml/out/` 得到自己的報表。
> 下文引用的實測數字僅為**開發時的參考觀測**，不是本 repo 的交付物。

## 為什麼不能只用「單行 NLP」

這 4 種攻擊多是**跨行語意/統計異常**，單看一行文字幾乎都合法：

| 攻擊 | 單行看 | 真正的破綻（跨行）|
|---|---|---|
| S 欺騙 | 假距離行文字與真的相同 | 同一秒出現兩筆 `[Sensor] Updated distance` |
| T 竄改 | `BadUserAccessDenied` 是合法系統訊息 | 同一 session 反覆對唯讀節點寫 |
| R 否認 | `[Motor] Distance too close...` 完全合法 | **無法歸屬**（破綻不在文字裡）|
| RP 重放 | 重放行文字合法 | 內容+內嵌時間戳與過去某筆完全相同 |

→ 所以管線核心是「解析 → 結構化特徵（含跨行）→ 序列/語意模型」，不是逐行分類。

## 三層架構

```
raw log ─▶ [第1層] 解析+特徵工程 ─▶ [第2層] 序列模型 ─▶ [第3層] NLP語意嵌入
           parse_logs.py            DeepLog(LSTM)        sentence-embedding
           規則即可抓 S/T/RP        抓時序異常(T 最強)    泛化到未見過的新模板
```

### 第 1 層：parse_logs.py

把每行解析成：`ts / level / cat / source / dist / guid / template / template_id`，
並萃取跨行特徵：
- `sensor_events_in_sec` — 每秒 sensor 事件數（**S**：>1 異常）
- `dist_ts_occurrence` — (內嵌時間戳,數值) 第幾次出現（**RP**：>1 異常）
- `session_denied_cumcount` — 同 session write-denied 累計（**T**：>1 異常）
- `seq_pos` + `template_id` — 模板序列（餵 **第 2 層** DeepLog）

標籤由各場景的 `anomaly_marked.log` 自動對回（`label`, `attack_type`）。

輸出 `ml/out/`：`parsed_all.csv`、`templates.csv`、`summary.txt`。

**實測特徵可分性**（summary.txt）：

| 攻擊 | 可分特徵 | 該特徵 max（正常 baseline）|
|---|---|---|
| S | sensor_events_in_sec | 2（正常 1）|
| T | session_denied_cumcount | 5（正常 0）|
| RP | dist_ts_occurrence | 4（正常 1）|
| **R** | **無** | 三特徵全 0/1，**與正常不可分** |

> S/T/RP 各有一個乾淨可分的統計特徵；**R 在所有行為特徵上與正常一致**。
> 這在數據上量化了「R 最難自動偵測」，並由 `ablation_leakage.py` 的消融實驗證實
> （輸出 `out/ablation_leakage.txt`）。

#### OPC UA Part 22 LogRecord 欄位（已於 C 端實作）

log 產生端（`sensor_pub.c` / `motor_sub.c` / `aggregation_server.c`）現在直接輸出
**OPC UA Part 22 (Diagnostics) Table 8 `LogRecord`** 的標準欄位，`Severity` 依 **Table 9**
為 1–1000 的數值：

```
[2026-08-03 09:50:22.553 (UTC)] info/application	[Sensor] Updated distance: 38.4 cm \
  | Severity=75 | SourceName=Sensor | EventType=application | SourceNode=ns=1;s=SensorSource
```

| LogRecord 欄位 | 來源 | 狀態 |
|---|---|---|
| `Time` (必填) | 時間戳 | ✓ |
| `Severity` (必填) | log level | ✓ Table 9 數值化（info=75 / warn=175 / error=225 / fatal=500）|
| `Message` (必填) | 訊息本體 | ✓ |
| `SourceName` | Sensor / Motor / System | ✓ |
| `EventType` | log category | △ 以 category 近似 |
| **`SourceNode`** | **session 身分（伺服器蓋章）** | ✓ **不可偽造 —— 見下** |
| `TraceContext` | — | ✗ 缺（無跨 server 關聯）|

##### SourceNode 為什麼必須由伺服器蓋章

`SourceNode`（0:NodeId，「這筆記錄來自哪個 Node」）是規範**早就定義好**的欄位，
先前實作沒有填 → log 無法歸屬來源 → R(否認) 在原理上無法偵測
（`ablation_leakage.py` 消融實驗：三個 ML 模型真實 R recall 都是 **0%**）。

但**光是加一個文字欄位沒有用**：否認攻擊會逐字複製真實 log 的格式
（見 `attacks/repudiation_attack.c`），行內的任何欄位都能照抄。

正解是讓**伺服器**在收到寫入時，依它自己觀察到的 **session 身分**蓋章：

| 寫入者 | session | 伺服器蓋的 SourceNode |
|---|---|---|
| `sensor_pub` | `SensorSource` | `ns=1;s=SensorSource` ✓ 已驗證 |
| `motor_sub` | `MotorSource` | `ns=1;s=MotorSource` ✓ 已驗證 |
| **攻擊者（匿名）** | — | **`null`** ✗ 未驗證 |

攻擊者能偽造 log 內容，卻無法冒用 session 身分。實測結果：

```
真 Sensor       : [Sensor] Updated distance: 38.4 cm ... | SourceNode=ns=1;s=SensorSource
攻擊偽造 Motor  : [Motor] Distance too close (8.6) ...  | SourceNode=null
```

→ **R 從「任何 ML 模型都測不到」變成「一條規則就能測到」**，
印證了本專案的核心結論：R 的正解是工程手段，不是模型手段。

> **相容性**：parser 同時支援新舊格式。舊格式資料的 `lr_SourceNode` 為 `None`，
> 核心特徵欄位完全不變 —— **所有既有實驗結果仍然有效**。
> 要取得 `SourceNode` 需以新版程式重新採集。

#### 數值特徵（不經模板化）—— OT 場域的補充

模板化會把 `distance: 45.2 cm` 和 `38.7 cm` 壓成同一個模板，**數值被丟掉了**。
但 OT 場域的破綻常常就在數值裡（本專案實證：DeepLog 對 RP 只有 50%，因為重放的
破綻是參數重複，序列模型原理上看不到）。

`parse_logs.py` 另外萃取四個「只看數值、不看文字」的特徵（零訓練，門檻取自純正常
baseline）：

| 特徵 | 規則 | 本資料實測 |
|---|---|---|
| `dist_out_of_range` | `dist ∉ [2, 50]` 物理量程 | 0 筆（隱蔽攻擊的假值都在合法範圍內）|
| `dist_delta` | 相鄰讀數變化率 | **無效** —— `read_distance()` 是 `rand()`，正常本身就劇烈跳動 |
| **`sensor_no_echo`** | sensor 讀數 motor 沒收到 | **S recall 100%，FPR 0.51%** ⭐ |
| `motor_logic_violation` | 角度 ≠ (距離<20 ? 0 : 90) | 0 筆 |

**`sensor_no_echo` 是最有價值的一條**：真 sensor 的讀數會被 motor 訂閱收到並回報，
必然在下游留下痕跡。攻擊者是把假 log **直接注入彙整伺服器**，沒有真的改動 sensor
節點 → 那個值 motor 從來沒收到過。這檢查的是**物理因果**，不是統計離群。

> ⚠️ **誠實的結果**：在本資料上數值規則**沒有獨有貢獻**（0 筆），它抓到的 15 筆
> 全被既有統計規則涵蓋，OR 疊加後 F1 反而從 0.592 降到 0.527。
> 原因是本專案的 S 攻擊同時觸發兩種破綻。數值規則的獨立價值需要「低頻率注入」的
> 隱蔽攻擊變體才能顯現 —— 詳見 [`out/numeric_eval.txt`](out/numeric_eval.txt)。

### 第 2 層：DeepLog / LSTM 序列模型

把每場景轉成 `template_id` 序列，LSTM 學「正常下一個模板」的分布；
實際模板不在預測 top-k → 異常。實測上它**只有對 T(竄改) 是穩定可靠的**
（5 個 seed 全部 100%，std=0）；對 S/RP 表現不穩，對 R 無效。

### 第 3 層：NLP 語意嵌入

用 sentence-embedding（all-MiniLM）把 template 轉向量，對「沒見過的新模板」有語意
泛化力。可作 DeepLog 輸入特徵，或接 Isolation Forest / autoencoder 做無監督偏離偵測。

### 第 4 層：多變量序列模型（mvdeeplog / mvlstm_ae）

前三層把每一行壓成一個 **模板 ID**，於是「值」與「節律」被丟掉了。S(欺騙) 偽造的
sensor 讀數用的是**與正常讀數完全相同的模板**，所以在模板這個觀測維度上根本不存在
—— 換更大的 LSTM 不會有幫助，這是**輸入表示**的問題不是容量問題。第 4 層把觀測從
「模板序列」換成「(模板, 間隔, 值) 的多變量序列」：

| 檔 | 型態 | 形狀 |
|---|---|---|
| `mvdeeplog.py` | **預測式** LSTM | 吃 W 步 → 三個頭預測下一步的 `(模板, dt, 值)`；分數 = CE + 兩個 Gaussian NLL，各自用純正常 val 標準化後加權 |
| `mvlstm_ae.py` | **重建式** LSTM Autoencoder | 只吃連續通道 `log1p(dt_source) / dt_stream / 正規化 dist / val_mask`，壓成 latent 再解回；分數 = 重建 MSE，門檻取 val 高分位 |

兩者共用**完全相同**的資料管線（分流、baseline/test 切分、seen-only、正規化只由
train 估），所以報表可逐行對照，回答「重建式 vs 預測式，哪個對數值異常更有效」。

三個關鍵設計決定（都寫在各檔開頭的註解裡）：

- **預測目標也要換，不只換輸入。** 若輸出仍然只有模板，S 依舊不可見 —— 異常必須
  出現在預測目標裡，所以 `head_dt` / `head_val` 是必要的而非加分項。
- **輸入只放原始觀測，不放衍生的偵測特徵。** 刻意排除 `sensor_no_echo` /
  `dist_ts_occurrence` / `sensor_win_count` 等 —— 那些是規則的答案，放進去只是
  「規則換一種寫法」（且 `sensor_no_echo` 用到未來 5 秒資訊，是 lookahead）。
  也不放 pair 編號：那是身分不是行為，拓樸擴張時就得重訓。
- **pair 分流是架構前提，不是可調選項。** aggregation_server 把 N 組 pair 匯進同一份
  檔案，檔案順序是 N 條各自規律的循環隨機交錯的結果 → bigram 的「前一個模板」幾乎
  不帶資訊。分流邊界必須對齊因果單元（motor i 只訂閱 sensor i，兩者必須同流）。
  用 `ngram_detector.py --compare-streams` 複現這個對照。

**兩階欺騙威脅模型**（`attacks/physics_aware_spoof.c`）：naive spoof 注入量程內均勻
亂數，與前值差很大，單步 |Δ| 檢定就能抓 → 不足以支撐「偵測有難度」。物理感知版
**先讀目標節點當前值**再注入附近的一小步，單步檢定失效；但攻擊者控制不了下一步
（真感測器從真值繼續遊走），於是相鄰增量呈負相關 —— 這個二階結構在單步上看不見、
需要至少兩步，正是序列模型該學、規則難寫的訊號。`check_spoof_tier.py` 用模型無關的
單步 |Δ| 檢定驗證這個難度差異確實只存在於**值**維度。

**逐秒評估**（`second_level_eval.py`）：把逐行分數以 `(scenario, ts_sec)` 聚合成逐秒
指標。門檻取自 **val 集**（baseline 場景後 20%，訓練期間完全未使用）的正常秒分位數，
而不是評估集 —— 後者所報告的誤報率必然等於設計值（那是恆等式不是量測），且門檻參數
接觸了評估資料。改用 val 校準後，「設計誤報率」與「實測誤報率」是兩個不同的數，
兩者的落差本身就是結果。

## 評估指標

異常極不平衡（~0.2%），**不可用 accuracy**。用 **Precision / Recall / F1 / PR-AUC**，
並**分攻擊類別**報（R 註定低 recall，混在一起會被稀釋看不出來）。

**兩個必要的方法學要求**（先前版本缺少，已由 `sweep_deeplog.py` 補上）：
1. **報 PR 曲線與 PR-AUC**，而非單一 top-k 下的點估計 —— top-k 只是曲線上的一個工作點。
2. **多 random seed 報 mean ± std** —— LSTM 有隨機初始化，單次執行的差距可能只是雜訊。

## 檔案

**核心管線**
- `parse_logs.py` — 解析+特徵工程+LogRecord 對映 → `out/parsed_all.csv`
- `train_classic.py` — IsolationForest + RandomForest → `out/classic_results.txt`
- `deeplog.py` — 第2層 DeepLog(LSTM) → `out/deeplog_results.txt`
- `embed_semantic.py` — 第3層 語意偏離偵測 → `out/semantic_results.txt`
- `deeplog_semantic.py` — 第3層 語意向量 DeepLog → `out/deeplog_semantic_results.txt`

**第 4 層：多變量序列模型**
- `mvdeeplog.py` — **預測式** LSTM，三頭預測 (模板, dt, 值) → `out/mvdeeplog_results*.txt`
- `mvlstm_ae.py` — **重建式** LSTM Autoencoder，連續通道重建誤差 → `out/mvlstm_ae_results*.txt`
- `ngram_detector.py` — n-gram / bigram 零訓練對照組；`--compare-streams` 驗證分流邊界
- `second_level_eval.py` — 逐行分數 → **逐秒指標**，門檻由 val 校準 → `out/second_level_eval.txt`
- `check_spoof_tier.py` — 模型無關的單步 |Δ| 檢定，驗證兩階 spoof 的難度差異
- `diag_T_recover.py` — 多門檻診斷：神經 tmpl surprisal 能撿回多少 T → `out/diag_T_recover.txt`

**驗證與方法學**
- `ablation_leakage.py` — **R 消融實驗**：證明 R 的高分來自資料洩漏 → `out/ablation_leakage.txt`
- `sweep_deeplog.py` — **超參掃描 + PR 曲線 + 多 seed** → `out/sweep_deeplog.txt`, `out/pr_curve.csv`
- `hybrid_detector.py` — **混合偵測器實測**（第1層 OR/AND 第2層）→ `out/hybrid_results.txt`

**數值特徵（不經模板化）**
- `eval_numeric.py` — **數值規則偵測器** → `out/numeric_eval.txt`

**SourceNode 對照實驗（R 的正解驗證）**
- `collect_sourcenode.sh` — **採集含 SourceNode 的新格式 log**（含自動標記）
- `eval_sourcenode.py` — **有/無 SourceNode 對照** → `out/sourcenode_eval.txt`

**採集腳本**
- `collect_baseline.sh` — 產生純正常 baseline
- `collect_v2.sh` — 單一 pair，新格式（LogRecord + SourceNode）
- `collect_topo3.sh` — **三組 1:1 pair 匯進同一 aggregation_server**（第 4 層的主資料集），
  含 naive / physics-aware 兩階 spoof 場景

**其他**
- `eval_four_combined.py` — 四攻擊混合場景單獨評估 → `out/four_combined_eval.txt`
- `venv/` — PyTorch + sentence-transformers CPU 虛擬環境（不進版控，見下方環境建置）

## 重現

### 0) 環境（venv 不進版控，第一次要自己建）

```bash
cd stable/Aggregation_clientServer
python3 -m venv ml/venv
ml/venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
ml/venv/bin/pip install numpy pandas scikit-learn matplotlib scapy sentence-transformers
```

### 1) 採集資料（`attacks/logs/` 也不進版控，要自己跑）

```bash
./ml/collect_topo3.sh 10 2 2 1 1   # 短測，確認流程（約 20 分鐘）
./ml/collect_topo3.sh              # 正式採集（baseline 60 分 + 各攻擊場景）
```

> `.c` 比執行檔新時腳本會自動重編，直接跑即可。

### 2) 跑管線

```bash
cd stable/Aggregation_clientServer

# 第一步：解析（系統 python 即可）
python3 ml/parse_logs.py

# 傳統 ML / 第2層 / 第3層
python3 ml/train_classic.py
ml/venv/bin/python ml/deeplog.py
ml/venv/bin/python ml/embed_semantic.py      # 先跑，產生 embeddings
ml/venv/bin/python ml/deeplog_semantic.py

# 驗證與方法學（建議依此順序讀結果）
ml/venv/bin/python ml/ablation_leakage.py    # R 洩漏消融（最重要）
ml/venv/bin/python ml/hybrid_detector.py     # 混合偵測器
ml/venv/bin/python ml/sweep_deeplog.py       # 超參掃描（約 11 次訓練，較慢）
python3 ml/eval_numeric.py                   # 數值特徵規則（不經模板化）

# 第 4 層：多變量序列模型（topo3 資料集）
ml/venv/bin/python ml/ngram_detector.py --compare-streams   # 先確認分流邊界
SCENARIO_FILTER=topo3 DUMP_SCORES=1 ml/venv/bin/python ml/mvdeeplog.py
SCENARIO_FILTER=topo3 DUMP_SCORES=1 ml/venv/bin/python ml/mvlstm_ae.py
ml/venv/bin/python ml/second_level_eval.py   # 逐秒指標（需上面的 DUMP_SCORES=1）
ml/venv/bin/python ml/check_spoof_tier.py    # 兩階 spoof 難度差異（模型無關）
SCENARIO_FILTER=topo3 ml/venv/bin/python ml/diag_T_recover.py

# SourceNode 對照實驗（需重新採集資料）
./ml/collect_sourcenode.sh quick             # 先跑快速驗證（約 6 分鐘，確認流程）
./ml/collect_sourcenode.sh 30                # 正式採集（baseline 30 分 + 兩個攻擊場景）
python3 ml/parse_logs.py                     # 重新解析（新舊格式都會處理）
python3 ml/eval_sourcenode.py                # 對照：ML 的 0% vs 規則的 100%
```

> ⚠️ `quick` 模式的資料**僅供流程驗證**，攻擊潛伏時間被縮短，不要拿來當正式結果。
> 驗證完請 `rm -rf attacks/logs/sn_*` 再做正式採集。

> **注意**：`ablation_leakage.py` / `sweep_deeplog.py` / `hybrid_detector.py` 一律在
> **已關閉洩漏管道**的資料上評估。`deeplog.py`、`train_classic.py`、`eval_four_combined.py`
> 是**未關閉洩漏**的原始版本，其 R 分數為假高分，僅供對照用。

## 已知限制

- **樣本數少**：R=4, T=10, RP=8 → 屬案例級佐證，非統計顯著。要下嚴謹結論需重跑攻擊
  採集把每類提到 ≥50（注意：應**同步加長正常 baseline 維持 ~0.2% 的真實比例**，
  不是提高異常佔比 —— 真實比例本身是本研究的前提）。
- **`ST_20260731_003522` 場景已移除**：該次採集 motor 未正常運作（無 `motor.log`），
  無法做下游一致性檢查。移除後資料為 **23,923 行 / 37 異常**。
  ⚠️ 早期報表中的 **24,062 行 / 49 異常**是含該場景的數字，結論仍有效，只是資料基數
  不同。要完全對齊需重跑三個驗證實驗。
- **本機無 GPIO** 影響 R/S 的模板分布。已用 `ablation_leakage.py` 模擬有 GPIO 的情況，
  但嚴謹評估仍需在真實 GPIO 環境重採。
- **DeepLog 整體 PR-AUC 僅 ~0.12**：不是調參不足（整個網格都低），而是序列模型在本
  資料上的能力上限。
- 只有一份 baseline 場景，無法評估跨環境/跨時段的泛化。
