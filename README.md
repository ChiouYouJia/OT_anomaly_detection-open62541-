# OT 異常偵測 — OPC UA 測試床 + 多層偵測模型

在 [open62541](https://github.com/open62541/open62541) 上搭一套可重現的 OPC UA
感測／致動測試床，對它施加 **STRIDE** 攻擊，並比較「應用層 log 模型」與
「網路層圖模型」兩條偵測路線的實際能力上限。

> ⚠️ **本 repo 只收程式碼。** 實驗報告、論文草稿、量測數字、pcap、log、圖檔一律
> 不進版控（見 [`.gitignore`](.gitignore)）—— 每個人跑出來的數字取決於自己採集的
> 資料。README 中引用的數字是開發時的參考觀測，不是本 repo 的交付物；照各子模組的
> 「重現」段落跑一次，就會在自己機器上得到對應的報表。

> ⚠️ 攻擊程式僅供**你自己機器上、你自己系統**的授權安全測試與研究使用。

## 專案結構

| 目錄 | 內容 |
|---|---|
| [`Aggregation_clientServer/`](Aggregation_clientServer/) | **主要工作區**：client/server 架構的測試床 + 攻擊 + 偵測模型 |
| [`Aggregation_clientServer/ml/`](Aggregation_clientServer/ml/) | 應用層 **log** 異常偵測管線（見該目錄 [README](Aggregation_clientServer/ml/README.md)）|
| [`Aggregation_clientServer/net/`](Aggregation_clientServer/net/) | 網路層 **pcap / 圖 / GNN** 偵測管線（見該目錄 [README](Aggregation_clientServer/net/README.md)）|
| [`Aggregation_clientServer/attacks/`](Aggregation_clientServer/attacks/) | STRIDE 攻擊 PoC 原始碼 |
| `Aggregation_pubsub/` | PubSub 架構版本（含 DoS 測試）|
| `gds_sks_pub_sub/`、`sks_*`、`static_encrypt/` | PubSub 加密／SKS／GDS 的階段性實驗 |

## 測試床

```
       sensor_pub (OPC UA server @4842)
         ▲        ▲        ▲              ← N 台 motor 訂閱同一個 sensor
      motor1   motor2   motor3            （各綁 127.0.0.2/.3/.4，網路層才分得開）
         │        │        │
         └────────┼────────┘  各自把 log 寫進 ▼
                  ▼
       aggregation_server (OPC UA server @4840)
                  ▲
           Anomaly_client（讀取彙整後的 log）
```

彙整伺服器輸出 **OPC UA Part 22 (Diagnostics) Table 8 `LogRecord`** 的標準欄位，
`Severity` 依 Table 9 數值化。關鍵在 **`SourceNode` 由伺服器依它自己觀察到的 session
身分蓋章**，不是由寫入者填 —— 攻擊者能逐字複製 log 格式，卻無法冒用 session 身分，
匿名寫入一律蓋成 `null`。

## 攻擊（STRIDE）

| 程式 | 類型 | 手法 |
|---|---|---|
| `spoof_attack.c` | **S** 欺騙 | 匿名連 4840，注入量程內均勻亂數的假讀數 |
| `physics_aware_spoof.c` | **S**（第二階）| **先讀目標節點當前值**，再注入附近的一小步 → 單步檢定失效 |
| `tamper_attack.c` | **T** 竄改 | 打 sensor server 4842，對唯讀節點反覆寫入 |
| `repudiation_attack.c` | **R** 否認 | 匿名注入格式完全合法、無法歸屬來源的 log |
| `replay_attack.c` | **RP** 重放 | 先讀整份 CentralLog 再原樣重寫 |
| `stealth_spoof_attack.c` | 進階 | 低頻率、擬真的稀疏注入 |
| `compromised_node_attack.c`<br>`compromised_group_attack.c` | 進階 | **冒用合法身分**、流量完全正常、沒有任何攻擊邊 |

## 三個核心結論

1. **R(否認) 的正解是工程手段，不是模型手段。** R 在所有行為特徵上與正常一致，
   三個 ML 模型的真實 recall 都是 0%；伺服器蓋 `SourceNode` 之後，一條零訓練規則
   （`SourceNode == null`）就解決了。
2. **模板化丟掉了「值」與「節律」。** S 偽造的讀數用的是與正常完全相同的模板，
   在模板維度上根本不存在 —— 換更大的 LSTM 不會有幫助，這是**輸入表示**的問題。
   解法是把觀測換成 (模板, 間隔, 值) 的多變量序列，且**預測目標也要一起換**。
3. **靜態拓撲下 GNN 打不贏一條規則。** 「某台 motor 回報值 ≠ sensor 真值」本來就
   只需要一個純量表達，`report_dev_own > 0.1` 即 recall 100% / 零誤報。
   根因不是模型不夠強，是攻擊在該拓撲下太簡單 → 需要動態訂閱等更難的場景。

> 這三點的共同形狀：**先確認訊號在資料裡存不存在，再談模型。** 本專案已踩過五次
> 「先報了高分，才發現是洩漏」，因此每條管線都內建了消融與稽核步驟
> （`ml/ablation_leakage.py`、`net/audit_graph.py`），請務必跑。

## 環境建置

先去 open62541 pull v1.5.5：

```bash
cd open62541
mkdir -p build && cd build   # 如果已有 build 記得先刪掉
git submodule update --init --recursive
cmake -DCMAKE_BUILD_TYPE=Release \
      -DUA_ENABLE_PUBSUB=ON \
      -DUA_ENABLE_ENCRYPTION=ON \
      -DUA_ENABLE_ENCRYPTION_MBEDTLS=ON \
      -DUA_ENABLE_PUBSUB_SKS=ON \
      -DUA_NAMESPACE_ZERO=FULL \
      -DUA_BUILD_EXAMPLES=OFF \
      -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local ..
make
sudo make install
sudo ldconfig
```

Python 端（`ml/venv/` 不進版控，第一次要自己建）：

```bash
cd Aggregation_clientServer
python3 -m venv ml/venv
ml/venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
ml/venv/bin/pip install numpy pandas scikit-learn matplotlib scapy sentence-transformers
```

## 快速開始

```bash
cd Aggregation_clientServer

./run_all.sh                 # 啟動全部節點並跟 log（Ctrl-C 停止全部）
./run_all.sh -q -n 5         # 只啟動、5 台 motor、背景執行
```

log 落在 `logs/run_<時間戳>/`，其中 `anomaly.log`（彙整伺服器收到的全部 log，
含 `SourceNode`）是後續所有分析的輸入。接著：

- **log 偵測管線** → [`ml/README.md`](Aggregation_clientServer/ml/README.md)
- **網路／GNN 管線** → [`net/README.md`](Aggregation_clientServer/net/README.md)

## PubSub 分支的進度

PubSub 加密已完成到 SKS，但 SKS 尚需查證確切規範；加密後的封包有擷取問題
（可能要改 open62541 的程式碼解決金鑰取得）。`gds_server` 仍有不少 bug，
且 debug 與維護難度高。
