# `topo3_*` 攻擊日誌資料集

本目錄收錄論文第三章（攻擊資料集之建置）與第五章（實驗流程與結果）所使用的**全部**
原始應用層日誌。資料由 `ml/collect_topo3.sh` 於三組 1:1 配對拓樸上採集、由
`ml/mark_anomalies.py` 產生逐行真實標記，並由 `ml/parse_logs.py` 轉為結構化資料表
（`parsed_all.csv`）供偵測模型使用。

僅 `topo3_*` 進版控；其餘早期迭代（`v2_*`、`densitysweep_*`、`baseline_180min`）
不屬論文範圍，留於本機。

## 資料集規模

| 項目 | 數量 |
|---|---|
| 場景總數 | **71**（11 baseline + 60 含攻擊） |
| `anomaly.log` 逐行日誌 | **270,238** 行 |
| 標記異常行 | **1,404** 行（S 527／T 216／R 432／RP 229） |
| 原始檔案 | 1,039 檔，約 158 MB |

> 論文 §3.9 所列之「約 1.2×10³ 筆異常」與「1.71×10⁵ 筆逐行位置」係
> `parse_logs.py` 完成配對反交錯、模板抽取與窗長聚合**之後**的測試集口徑；
> 上表為未經處理之原始日誌口徑，兩者不應直接相比。

## 場景清單

| 場景類別 | 場景數 | 時長 | `anomaly.log` 行數 | 用途 |
|---|---|---|---|---|
| `topo3_baseline_60min_*` | 3 | 60 分 | 67,567 | 訓練與門檻校準 |
| `topo3_baseline_10min_*` | 2 | 10 分 | 10,966 | 訓練與門檻校準 |
| `topo3_baseline_ctrl_*` | 6 | 300 s | 17,222 | 正常對照（同 harness、關閉注入） |
| `topo3_Four_combined_*` | 24 | 300 s | 70,637 | 主評估場景（S＋T＋R＋RP 並行） |
| `topo3_R_only_*` | 24 | 300 s | 69,032 | 否認攻擊單類消融 |
| `topo3_Snaive_*` | 6 | 300 s | 17,308 | 天真欺騙（兩階威脅模型消融） |
| `topo3_Sphys_*` | 6 | 300 s | 17,506 | 物理感知欺騙（兩階威脅模型消融） |

切分依半監督設定：11 個 `baseline` 場景之前 80% 為訓練集、後 20% 為驗證集，
60 個含攻擊場景全數為測試集——模型訓練時僅見正常流量。

場景目錄名格式為 `topo3_<類別>_r<重複編號>_<採集批次時間戳>`；同一批次採集之場景
共用時間戳，並對應一份 `topo3_collection_report_<時間戳>.txt`（5 份，記錄每場景之
總行數、`SourceNode=null` 筆數與各 `SensorSource` 分佈，可用於核對本資料集之完整性）。

## 每個場景目錄的內容

| 檔案 | 說明 | 管線是否讀取 |
|---|---|---|
| `anomaly.log` | **主資料**。`Anomaly_client` 自聚合伺服器 `CentralLog` 收集之單一交錯日誌流，含伺服器加蓋之 `SourceNode` 等 LogRecord 欄位 | ✅ `parse_logs.py` |
| `anomaly_marked.log` | **真實標記**。`anomaly.log` 之標記版，異常行以 `>>>` 起首、行尾附 `# ⚠ [類別] 說明` | ✅ `parse_logs.py` 取標籤 |
| `agg.log` | 聚合伺服器自身視角 | ❌ 佐證用 |
| `sensor1..3.log` | 三個感測端各自視角 | ❌ 佐證用 |
| `motor1..3.log` | 三個致動端各自視角 | ❌ 佐證用 |
| `spoof_attack_p{1,2,3}.log` 等 | 各攻擊程式之 stdout，依配對分列 | ❌ 佐證用 |

只有 `anomaly.log` 與 `anomaly_marked.log` 會被偵測管線讀取；其餘各節點視角之日誌
保留於此，是為了讓單一交錯資料流中的每一行都能回溯至產生它的行程。

## 標記格式

`anomaly_marked.log` 之標記由 `mark_anomalies.py` 依伺服器加蓋之欄位與訊息語意產生，
判準與採集腳本逐字一致：

- `SourceNode = null`（匿名寫入）→ 依內容分為 **S**（`[Sensor]` 更新）、**R**（`[Motor]` 動作）
  或 **RP**（內容曾出現過之重複行）
- `BadUserAccessDenied` → **T**
- 其餘 → 正常

四類對應 STRIDE：S = Spoofing 欺騙、T = Tampering 竄改、R = Repudiation 否認、
RP = Replay 重放。標記僅供離線評估，偵測模型於推論時不可見。

取出全部異常行：

```bash
grep -h '^>>>' topo3_*/anomaly_marked.log          # 全部
grep -h '^>>>' topo3_*/anomaly_marked.log | grep '\[RP\]'   # 單類
```

## 已知資料狀況

- **`topo3_baseline_60min_20260815_222203` 為一次中斷之採集**：僅 2,377 行
  （另兩個 60 分場景為 32,599／32,591 行），且**無 `anomaly_marked.log`**。
  該次採集於 22:22 啟動、22:26 重啟為 `topo3_baseline_60min_20260815_222638`。
  此場景仍計入 11 個 baseline、其行數亦計入上表，因為論文之數據即在含它的資料集上
  產生；此處照原樣保留，不做事後修剪。`parse_logs.py` 在缺 marked 檔時標籤集為空，
  對 baseline 而言無影響（該場景本就全為正常流量）。

## 重現流程

```bash
cd Aggregation_clientServer/ml
python parse_logs.py          # attacks/logs/topo3_* → out/parsed_all.csv
python mvdeeplog.py           # 多變量預測式 LSTM
python mvlstm_ae.py           # LSTM 自編碼器
python ngram_detector.py      # n-gram / DeepLog 基線
python second_level_eval.py   # 逐秒聚合評估（論文主要報告粒度）
python diag_T_recover.py      # 竄改之運作點假象診斷
```

重新採集（非重現論文數據所必需，會產生新的場景時間戳）：

```bash
cd Aggregation_clientServer/ml
./collect_topo3.sh            # 採集 → attacks/logs/topo3_*
python mark_anomalies.py      # 產生 anomaly_marked.log
```

攻擊程式原始碼見 `attacks/*.c`，受測系統見 `Aggregation_clientServer/*.c`。
