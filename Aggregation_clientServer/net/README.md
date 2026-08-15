# 網路流量異常檢測 — Spoofing 攻擊 pcap → ML

打 **Spoofing 攻擊**、**抓取網路封包(pcap)**、用**機器學習**做異常檢測的管線。

> 與 `../ml/` 互補：`ml/` 解析『應用層 log 文字』；本管線改抓『網路封包』，
> 用**封包/流量統計特徵**做無監督異常偵測。兩者資料來源不同、可交叉佐證。

## 為什麼流量統計就能抓到 spoof

`attacks/spoof_attack` 冒充 sensor **匿名連上** `aggregation_server@4840`，把偽造
log 稀疏注入。它在應用層很隱蔽（假距離值擬真、格式一致），但在**網路結構**上
藏不住：它是「多出來的一個 client」。注入的那幾秒，loopback 上會多出：

| 破綻 | 對應特徵 |
|---|---|
| 多一條到 :4840 的 TCP 連線 | `n_conns`, `uniq_client_ports`, `n_syn` ↑ |
| 額外送 Write 請求 | `n_pkts_c2s`, `bytes_c2s`, `max_payload` ↑ |
| 只有少數秒偏離 | 天然的不平衡異常偵測設定 |

所以我們把流量聚合成「每秒一列」的統計特徵，讓 IsolationForest 學正常秒的分布，
偏離的秒就是候選異常。**刻意不解 OPC UA binary payload** —— 破綻在流量結構，
不在單一封包內容，這樣也更穩健、跨版本可用。

## 推廣到 R/T/RP：誠實的可偵測性評估

同一套流量方法能不能抓 R(否認)/T(篡改)/RP(重放)？取決於**每種攻擊在網路層
是否留下痕跡**。四種攻擊的網路行為（讀原始碼得出）：

| 攻擊 | 連的 server | 手法 | 流量層痕跡 | 流量 ML 預期 |
|---|---|---|---|---|
| **S** 欺騙 | 4840 | 匿名寫 CentralLogIn | 多一條連線 + 額外 Write | **抓得到** ✓（已驗證 Recall 1.0）|
| **R** 否認 | 4840 | 匿名寫 CentralLogIn（同 S）| 多一條連線 | **測得到「有攻擊者」，但與 S 難分**⚠ |
| **T** 篡改 | **4842** | 匿名 read + 寫唯讀節點被拒 | 多一條連線 + 被拒回應 | **抓得到** ✓ |
| **RP** 重放 | 4840 | 先 read 整個 CentralLog 再重寫 | 多一條連線 + **大 read 回應** | **抓得到**（大 read 很顯眼）✓ |

**關鍵誠實結論**：
- 流量 ML 抓的本質是「**多出一個匿名 client**」這個共通破綻。對 S/T/RP 有效，
  因為它們都多開連線、且各有額外可辨識的流量（T 的被拒、RP 的大 read）。
- **R 在流量層與 S 幾乎相同** —— 都是「匿名連 4840 寫 CentralLogIn」。流量 ML 會
  標記出「有攻擊者連進來」，但**無法區分這是 R 還是 S**。R 的真正破綻是「無法歸屬
  身分」，那不在流量結構裡，要靠 server 蓋 SourceNode 的工程手段解（見 `../ml/`）。
- ⚠ **T 打的是 4842，不是 4840**。因此 `capture_attacks.sh` 抓 `4840 or 4842`；
  舊的 `capture_spoof.sh` 只抓 4840，用來測 T 會完全漏掉。

> 這條結論與 `../ml/` 的 log 管線一致：S/T/RP 各有可分特徵，**R 註定難以自動偵測**。
> 本管線用**流量**再次獨立驗證了這個排序。

## 權限（抓 loopback 需要 CAP_NET_RAW）

**先直接跑 `./net/capture_spoof.sh`**（不用 sudo）。腳本會先自我檢查能否在 `lo`
上抓包，能就直接開始 —— 多數環境（含本機，tcpdump 已 setcap）不需要任何額外授權。

若腳本回報無權限，做**一次性**授權（擇一），之後就免 sudo：

```bash
# (建議) 給 tcpdump capability：
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

# 或 加入 wireshark 群組（需登出再登入才生效）：
sudo usermod -aG wireshark $USER
```

> ⚠️ 不建議用 `sudo ./net/capture_spoof.sh`：sudo 下 `$USER` 會變成 root，
> 且不必要地用特權跑整條管線。授權一次後用一般身分跑即可。

## 三步跑完

```bash
cd stable/Aggregation_clientServer

# 1) 打 spoof + 抓流量（benign 120s + spoof 120s；數字可調）
./net/capture_spoof.sh                 # 或 ./net/capture_spoof.sh 300 300
#    產出 net/captures/spoof_<STAMP>/{benign,spoof}.pcap + spoof_attack.log

# 2) pcap → 每秒 flow 統計特徵 CSV（需 venv 的 scapy）
ml/venv/bin/python net/pcap_to_features.py net/captures/spoof_<STAMP>
#    產出 benign_flows.csv / spoof_flows.csv

# 3) ML 異常檢測（IsolationForest 在 benign 訓練、在 spoof 偵測）
ml/venv/bin/python net/detect_net.py net/captures/spoof_<STAMP>
#    產出 net_detect_results.txt（P/R/F1 + PR-AUC）+ spoof_scored.csv
```

`quick` 模式（縮短攻擊潛伏期，確保注入落在抓取窗內，供流程驗證）：

```bash
./net/capture_spoof.sh 60 60 quick
```

## 測試 R / T / RP（多攻擊通用腳本）

`capture_attacks.sh` 是 `capture_spoof.sh` 的通用版，可指定攻擊類型，且抓取
**同時涵蓋 4840+4842**（T 打 4842，必須抓）：

```bash
# 單獨場景（benign + 單一攻擊）
./net/capture_attacks.sh R  300 300      # 否認
./net/capture_attacks.sh T  300 300      # 篡改（打 4842）
./net/capture_attacks.sh RP 300 300      # 重放
./net/capture_attacks.sh S  300 300      # 欺騙（等同 capture_spoof.sh）
./net/capture_attacks.sh all 300 300     # 四攻擊同時（混合場景）

# 然後同樣兩步（會依資料夾名自動判斷攻擊類型、選對標籤來源）
ml/venv/bin/python net/pcap_to_features.py net/captures/<atk>_<STAMP>
ml/venv/bin/python net/detect_net.py       net/captures/<atk>_<STAMP>
```

各攻擊的 **ground truth 標籤來源**（皆取自 server 端紀錄，不依賴會遺失的攻擊 stdout）：

| 攻擊 | 標籤依據（server 端）|
|---|---|
| S | anomaly.log 同秒雙報 sensor（+ spoof_attack.log 佐證）|
| T | anomaly.log / sensor.log 的 `BadUserAccessDenied` |
| RP | anomaly.log 內容（含內嵌時間戳）重複出現 |
| R | anomaly.log 中 `SourceNode=null` 的 `[Motor]` 行；**若 log 無 SourceNode 欄位則標不到**（R 本就難偵測）|

## 檔案

| 檔 | 作用 |
|---|---|
| `capture_spoof.sh` | S 專用：啟動系統 + tcpdump 抓 lo:4840 + baseline/spoof → 兩份 pcap |
| `capture_attacks.sh` | **多攻擊通用**：S/R/T/RP/all，抓 4840+4842 |
| `pcap_to_features.py` | scapy 解析 pcap → 每秒 flow 特徵；依資料夾名自動判類型與標籤來源 |
| `detect_net.py` | IsolationForest 無監督偵測；報 P/R/F1/ROC-AUC/PR-AUC + 特徵診斷 |
| `captures/` | 每次抓取一個 `<atk>_<STAMP>/` 子資料夾 |

## 每秒特徵（只用封包標頭/大小，不解 payload）

`n_pkts` `n_pkts_c2s` `n_pkts_s2c` `bytes_c2s` `bytes_s2c` `n_conns` `n_syn`
`n_fin_rst` `uniq_client_ports` `max_payload`

## 標籤與指標

- **標籤**：`benign.pcap` 全 0；`spoof.pcap` 依 `spoof_attack.log` 的注入時間戳，
  把有注入的那一秒標 1（真實比例：異常秒極少 → 不平衡）。
- **指標**：異常秒稀少，**不用 accuracy**。報 **Precision / Recall / F1**（單一門檻
  工作點）與 **ROC-AUC / PR-AUC**（與門檻無關）。`detect_net.py` 另印「注入秒 vs
  正常秒平均特徵」，說明模型抓到的破綻來自哪些特徵。

## 方法學注意

- **無監督、無洩漏**：只用 `benign` 訓練；攻擊資料不參與訓練，標準化也只 fit 在
  benign，避免測試分布資訊洩漏。
- **退化保護**：若 benign 幾乎零變異（抓太短/流量太規律），IsolationForest 無鑑別力，
  程式自動改用「與 benign 平均的標準化歐氏距離」兜底並在報告中註明。正式評估請
  加長 benign 抓取時間以取得自然變異。
- **loopback 特性**：本機用 lo 抓包（sensor/server/attacker 同機）。真實部署跨主機時
  特徵定義相同，但需在對應介面（非 lo）抓取。
