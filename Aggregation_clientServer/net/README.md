# 網路流量異常檢測 — Spoofing 攻擊 pcap → ML

打 **Spoofing 攻擊**、**抓取網路封包(pcap)**、用**機器學習**做異常檢測的管線。

> 與 `../ml/` 互補：`ml/` 解析『應用層 log 文字』；本管線改抓『網路封包』，
> 用**封包/流量統計特徵**做無監督異常偵測。兩者資料來源不同、可交叉佐證。

> ⚠️ **本 repo 只收程式碼。** pcap、圖資料集、實驗報告、設計文件一律不進版控
> （見根目錄 `.gitignore`）。下文的實測數字是開發時的參考觀測，不是交付物 ——
> 照〈[三步跑完](#三步跑完)〉／〈[圖與 GNN](#圖與-gnn)〉跑一次會得到自己的報表。
> 部分程式的開頭註解引用了這些本機文件（`TODO_next_experiments.md` 等），
> 那是開發脈絡的紀錄，不影響執行。

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

## 圖與 GNN

上面的管線把每一秒壓成一個**特徵向量**，丟掉了「誰連了誰」。但四種攻擊在應用層各自
隱蔽，在**連線結構**上卻都是「多出一個端點／一條邊」—— 這正是 GNN 的長處。

`build_graph.py` 把 pcap + log 建成「**每秒一張圖**」：節點 = OPC UA 端點
（`agg_server:4840` / `sensor_server` / `motor1..N` / `anomaly_client` / 攻擊時才出現的
`attacker`），邊 = 該秒兩端點間的 TCP 流量，邊特徵取自流量統計、節點特徵取自 log。

| 模型 | 任務 | 定位 |
|---|---|---|
| `egraphsage.py` | **邊分類** | E-GraphSAGE (Lo et al., NOMS 2022) 忠實實作：鄰域聚合改聚合**邊特徵**、邊嵌入 = 兩端節點嵌入串接 |
| `graph_clf.py` | **圖級分類** | 為 `compromised_node` 設計 —— 攻擊者冒用合法身分、流量完全正常、**沒有任何攻擊邊**，邊分類器對它結構性失明；必須把整秒的圖當一個樣本，讓模型自己聚合出「這群節點彼此不一致」 |
| `gnn_baseline.py` | 單類異常偵測 | 只用 benign 訓練、多 seed 報 mean ± std、不用 accuracy |
| `rf_baseline.py` | **不用圖的對照** | GNN 的價值主張是「圖結構帶來額外資訊」。若只看單條邊特徵的 RandomForest 就一樣好，圖結構沒有加值 —— 這支就是用來拆穿這件事的 |
| `router_fusion.py` | 融合策略對比 | 單一最佳層 vs 全部 OR 疊加 vs **按攻擊類型分工路由**，同資料同測試集 |

**誠實結論（必讀）**：在**靜態拓撲**下，一條零訓練規則 `report_dev_own > 0.1` 在
compromised 與 compromised_group 上就是 recall 100% / benign 零誤報，GNN 在告警路徑
上毫無貢獻 —— 因為「某台 motor 回報值 ≠ sensor 真值」本來就只需要一個純量表達。
**根因不是模型，是攻擊在該拓撲下太簡單。** `capture_topo_rotate.sh` 讓訂閱關係在採集
期間週期性輪換，打掉這條規則賴以成立的「訂閱固定不變」前提，才是有意義的評估場景。

```bash
# 1) 採集（保留 log 與 pcap，兩者時間對齊）
./net/capture_topo.sh                    # 1 sensor + N motor 星狀
./net/capture_topo_multi.sh              # M sensor + N motor 多對多
./net/capture_topo_rotate.sh             # 訂閱關係週期輪換（打掉靜態規則）

# 2) 建圖 + 稽核（稽核務必跑，見下）
ml/venv/bin/python net/build_graph.py  net/captures/<dir>
ml/venv/bin/python net/audit_graph.py  net/captures/<dir>

# 3) 模型
ml/venv/bin/python net/rf_baseline.py  net/captures/<dir>   # 先跑對照組
ml/venv/bin/python net/egraphsage.py   net/captures/<dir>
ml/venv/bin/python net/graph_clf.py    net/captures/<dir>
ml/venv/bin/python net/gnn_ablation.py net/captures/<dir>
```

> **`audit_graph.py` 不是可選步驟。** 本專案已經踩過五次「先報了高分，才發現原因」的
> 洩漏：攻擊專屬模板、parser 產物、邊標籤把整秒正常通道標成攻擊、整數秒對齊的計時
> 假象、ground truth 記號 `#MAL` 讓 log 行長 5 bytes 直接反映在 pcap 位元組數。
> 每一次都是事後才抓到 —— 這支腳本把「事後回頭查」變成「建圖後就自動查」。

### 為什麼需要 `bindsrc.c`

三台 motor 跑在同一台機器上，來源 IP 全是 `127.0.0.1`，只有隨機 client port 不同 →
pcap 無法穩定分辨「這條連線是哪一台 motor」，GNN 的三個 motor 節點會塌縮成無法對應的
匿名節點。本專案使用的 open62541 版本，其 POSIX TCP 連線管理器**沒有 source-address
參數**，改 client 程式碼也做不到。所以用 `LD_PRELOAD` 攔截 `connect()` 綁定指定來源 IP
（127.0.0.2/.3/.4），是不動函式庫、不動 C 邏輯的最小侵入解法。

```bash
gcc -shared -fPIC -o net/bindsrc.so net/bindsrc.c -ldl    # 採集腳本會自動編
```

## 檔案

| 檔 | 作用 |
|---|---|
| **採集** | |
| `capture_spoof.sh` | S 專用：啟動系統 + tcpdump 抓 lo:4840 + baseline/spoof → 兩份 pcap |
| `capture_attacks.sh` | **多攻擊通用**：S/R/T/RP/all，抓 4840+4842 |
| `capture_topo.sh` | 1 sensor + N motor：同時採集 log 與 pcap（GNN 用），每場景獨立 pcap |
| `capture_topo_multi.sh` | M sensor + N motor 多對多拓撲 |
| `capture_topo_rotate.sh` | 訂閱關係週期輪換，破壞「靜態訂閱」前提 |
| `bindsrc.c` | `LD_PRELOAD` 綁定 outbound 來源 IP，讓三台 motor 在網路層可分 |
| **特徵／建圖** | |
| `pcap_to_features.py` | scapy 解析 pcap → 每秒 flow 特徵；依資料夾名自動判類型與標籤來源 |
| `build_graph.py` | pcap + log → 每秒一張圖（nodes/edges/graphs/meta） |
| `backfill_win_feats.py` | 把 sensor 窗內樣本欄位補進**既有**舊資料集（不必重跑 pcap 解析）|
| `audit_graph.py` | **建圖後的防洩漏／資料健康稽核** —— 必跑 |
| **模型** | |
| `detect_net.py` | IsolationForest 無監督偵測；報 P/R/F1/ROC-AUC/PR-AUC + 特徵診斷 |
| `egraphsage.py` | E-GraphSAGE 邊分類 |
| `graph_clf.py` | 圖級分類（針對 compromised）|
| `gnn_baseline.py` | GNN 單類異常偵測 baseline |
| `rf_baseline.py` | RandomForest 邊分類，**不用圖的對照組** |
| `gnn_ablation.py` | 值特徵／圖結構／時序的消融 |
| `router_fusion.py` | 融合策略對比：單一最佳層 vs OR 疊加 vs 分工路由 |
| `hop2_diag.py` | 診斷：peer 聚合為何對偵測沒有貢獻 |
| `captures/` | 每次抓取一個 `<atk>_<STAMP>/` 子資料夾（**不進版控**）|

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
