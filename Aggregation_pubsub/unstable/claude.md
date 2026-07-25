# CLAUDE.md

這份文件給 Claude Code 用，說明這個專案的架構、已知問題與除錯歷史，避免重複踩過的坑。

## 專案概觀

一個基於 [open62541](https://open62541.org/)（OPC UA C library，目前用的是 1.5.x）的分散式感測聚合系統，共四個獨立執行檔，都在同一台機器（hostname `MSI`）上跑，彼此用 OPC UA Client/Server 與 PubSub（UDP multicast）通訊：

| 檔案 | 角色 | Port / 協定 |
|---|---|---|
| `sensor_pub.c` | 距離感測器模擬，隨機產生距離值 | OPC UA Server @ 4842；PubSub Publisher @ `opc.udp://224.0.2.14:4843/`；同時是 syslog client 連到 4840 |
| `motor_sub.c` | 依距離控制伺服馬達（透過 lgpio） | OPC UA Server @ 4801；PubSub Reader（訂閱同一組 multicast）；同時是 syslog client 連到 4840 |
| `aggregation_server.c` | 聚合中心，彙整 sensor 的距離、統一收集三支程式的 log | OPC UA Server @ 4840；同時是 client（**非阻塞 `connectAsync`**）連到 sensor_pub 的 4842 |
| `Anomaly_client.c` | 訂閱 Aggregation Server 的 `CentralLog`（**String 陣列**），模擬 AIOps 消費端 | OPC UA Client，連到 4840 |

資料流：
- `sensor_pub` 透過 PubSub UDP multicast 把距離廣播出去 → `motor_sub` 訂閱後控制馬達。
- log 轉送管線：`sensor_pub` / `motor_sub` 把每行 log 寫進 `aggregation_server` 的 **`CentralLogIn`**（scalar String 寫入口）→ server 的 `onWrite` callback 把它 append 進 **`CentralLog`**（String 陣列 ring buffer，最近 256 行，每行前綴 `#<seq> `）。
- `aggregation_server` 另外會主動連到 `sensor_pub` 的 4842，訂閱 `DistanceValue`，寫進自己的 `AggregatedDistance` 節點。
- `Anomaly_client` 訂閱 `CentralLog`（陣列），用 `seq` 去重：一連上先補歷史、之後即時串流，不漏接。異常偵測邏輯掛在其 handler 內標 `👉` 的那行。

> 關鍵節點：`CentralLogIn`（scalar，寫入口）→ `CentralLog`（String[] ring buffer，訂閱來源）。**寫要寫 `CentralLogIn`，讀/訂閱要用 `CentralLog`。**

## 建置

⚠️ **本機地雷**：這台機器的 `pkg-config --libs open62541` 會把 mbedtls 輸出成壞格式的 `-l/絕對路徑.so`，用 `$(pkg-config --cflags --libs open62541)` 會連結失敗（`cannot find -l/usr/lib/.../libmbedtls.so`）。要改成 **直接帶 `.so` 路徑**：

```bash
MBED="/usr/lib/x86_64-linux-gnu/libmbedtls.so /usr/lib/x86_64-linux-gnu/libmbedx509.so /usr/lib/x86_64-linux-gnu/libmbedcrypto.so"
CF="$(pkg-config --cflags open62541)"; BASE="-L/usr/local/lib -lopen62541 -lpthread -lm -lrt $MBED"
gcc -o aggregation_server aggregation_server.c $CF $BASE
gcc -o motor_sub  motor_sub.c  $CF $BASE -llgpio
gcc -o sensor_pub sensor_pub.c $CF $BASE
gcc -o Anomaly_client Anomaly_client.c $CF $BASE
```

除錯懷疑記憶體問題時，優先用 ASan 版本重編：

```bash
gcc -g -O0 -fsanitize=address -o motor_sub_asan  motor_sub.c  $CF $BASE -llgpio
gcc -g -O0 -fsanitize=address -o sensor_pub_asan sensor_pub.c $CF $BASE
```

執行順序建議：先起 `aggregation_server`，再起 `sensor_pub` / `motor_sub`，最後起 `Anomaly_client`。三支背景輪詢程式都有 3 秒重試機制，順序其實不嚴格要求。

## 重要架構原則（除錯血淚教訓，修改前務必遵守）

### 1. `customLogger` 絕對不能呼叫任何 `UA_Client_*` / `UA_Server_*` API

`motor_sub.c` 和 `sensor_pub.c` 都把 `customLogger` 同時裝在自己的 server logger 和 syslog client logger 上。這代表 `customLogger` 可能在**任何** server/client 內部事件處理的呼叫堆疊中被觸發。

如果 `customLogger` 裡呼叫了任何 `UA_Client_*`（例如 `writeValueAttribute`、`getState`），會造成：
- 阻塞當下正在處理的 handshake，導致對方逾時（曾經讓 Aggregation Server 永遠連不上 sensor_pub）。
- 在同一呼叫堆疊裡重入同一個 client/server 物件的內部狀態機，導致 segfault。

**目前的解法**：`customLogger` 只做兩件事——組字串、`enqueue_log()` 排進一個固定大小的環狀佇列。真正的網路發送（`flush_log_queue_once()`）只從 `main()` 的迴圈呼叫，且每個 tick 最多送一筆。**不要**把發送邏輯搬回 logger 裡。

### 2. `customLogger` 展開 log 一律用 `UA_String_vformat`，絕不用 glibc 的 `vsnprintf`（取代舊的 PUBSUB 特例）

open62541 的 log 格式字串用的是「`UA_String_format` 的規則」，比 C 標準多了 `%S`(UA_String)、`%N`(UA_NodeId)、`%Q`(QualifiedName) 等**自訂符號**（見 `plugin/log.h`）。丟給 glibc 的 `vsnprintf`，`%S` 會被當成 C 標準的**寬字元字串 `wchar_t*`**，glibc 拿下一個 vararg（其實是 `UA_String`）當寬字串指標去掃 → **SEGV**（ASan backtrace 落在 `__wcsnlen_avx2`）。這與類別無關（PUBSUB、SECURECHANNEL 都會中）。

**目前的解法**：`customLogger` 改用 open62541 自家的 va_list 版格式化器 **`UA_String_vformat(&out, msg, args)`**（內建 `UA_Log_Stdout` 用的同一支）來展開，`%S`/`%N`/`%Q` 都會印成可讀真實值。**不要**改回 `vsnprintf`，也**不需要**再對 PUBSUB 做特例（舊的「只 guard PUBSUB」是誤判 `%s`，其實兇手是 `%S`，見 `debug_log.md` 問題 4→6）。`UA_String_vformat` 只做字串格式化、不碰 client/server 狀態，符合原則 1。

### ~~2-舊~~（已作廢）只對 `UA_LOGCATEGORY_PUBSUB` 不展開參數

原以為 PUBSUB 崩潰是 `%s`+沒 null terminator，只 guard PUBSUB 類別。**這是治標且診斷錯誤**：真正的符號是 `%S`，`SECURECHANNEL` 等其他類別也會中。已被上面的 `UA_String_vformat` 全面取代。

### 3. 三支程式的 syslog 重連邏輯是自製的，不是 open62541 內建

每支程式的 `main()` 迴圈手動維護 `syslog_connected` 旗標 + `last_try` 時間戳，每 3 秒嘗試一次 `UA_Client_connect`。斷線偵測靠每個 tick 呼叫 `UA_Client_getState` 檢查 `channelState != UA_SECURECHANNELSTATE_OPEN`。修改這段邏輯時要注意：斷線當下要記得 `clear_log_queue()`，避免重連後補送一堆過期 log。

### 4. server 主迴圈裡連別的 OPC UA server，一定要用非阻塞 `UA_Client_connectAsync`

`aggregation_server` 連 `sensor_pub:4842` 若用**阻塞式** `UA_Client_connect`，會在握手期間卡住整個主迴圈（進而讓自己的 server@4840 停止回應）。因為兩邊都是「server 又是對方的 client」，會互相 head-of-line block 形成**雙向死鎖**（症狀：廣播被拖成 3 秒、4842 每 2 秒殭屍連線、`AggregatedDistance` 不更新，見 `debug_log.md` 問題 5）。

**目前的解法**：改用 `UA_Client_connectAsync` + 狀態機（0 未連 / 1 async 握手中 / 2 已訂閱），每輪 `UA_Client_run_iterate` 推進握手，Session `ACTIVATED` 後才建訂閱。**不要**改回阻塞版。同理，任何在主迴圈或 callback 裡對別的 node/server 做同步呼叫都要警覺會不會卡住迴圈。

### 5. log 轉送用「環狀陣列 + 序號」不漏接；寫 `CentralLogIn`、訂閱 `CentralLog`

`CentralLog` 是 **String 陣列 ring buffer**（唯讀，最近 256 行，每行前綴 `#<seq> `），不是單值節點。writer 要寫的是 scalar 的 **`CentralLogIn`**，server 的 `onWrite` callback 才 append 進 `CentralLog`。**append 與整包 `UA_Server_writeValue` 刻意分離**：callback 只 append + 標 dirty，真正寫回陣列在主迴圈做（不在 callback 裡呼叫 `UA_Server_writeValue`，避免重入寫入服務）。消費端（`Anomaly_client`）靠 `#<seq>` 去重，一連上補歷史、之後即時串流。**不要**把 `CentralLog` 改回單值、也不要在 writer 端直接寫 `CentralLog`。

## 已知問題狀態（完整細節見 `debug_log.md`）

- ✅ 問題 1–4：log 模板未展開、BadTimeout、logger 阻塞 segfault、PUBSUB 崩潰——已解。
- ✅ 問題 5：雙向阻塞死鎖（3 秒廣播 / 2 秒殭屍連線 / `AggregatedDistance` 不更新）——已用 `connectAsync` 解。原「待查」的 3 秒排程與 2 秒連線就是這個，**不是** `run_iterate` 逾時值的問題。
- ✅ 問題 6：`%S` 寬字元 SEGV——已用 `UA_String_vformat` 解。
- ✅ 問題 7：CentralLog 漏接 / 晚連補不到歷史——已用環狀陣列 + 序號去重解。
- ℹ️ 關機時 subscriber 會噴 ~10 行 `PublishResponse: Received response for an unknown Subscription`：在飛的 PublishRequest 撞上已清掉的本地訂閱狀態的收尾競態，**無害**；要消掉可在 disconnect 前先 `UA_Client_Subscriptions_deleteSingle` 並 iterate 幾輪排空。
## 除錯方法論（這個專案適用）

這是多行程、跨網路的系統，光看單一支程式的 log 常常會誤判（例如把「同一次執行的 log 貼了兩次」誤認為是新結果，或是把兩條互不相關的連線誤認為是同一條的兩端視角）。有效的除錯順序：

1. **懷疑記憶體問題（segfault）**：不要用 log 猜，直接用 ASan 或 gdb 重編重跑拿 backtrace。這個專案已經證實過兩次，純靠 log 文字猜測 segfault 原因會猜錯方向。
2. **懷疑連線行為異常**：四支程式的 log 要**同時**拿，並對照 timestamp（注意 UTC 跟 UTC+8 混用，`aggregation_server`/`motor_sub`/`sensor_pub` 的 `printf` 是本地時區 UTC+8，但 `customLogger` 組出來的字串裡標的是 UTC，兩者相差 8 小時，比對時間點時要換算）。
3. 修改 `customLogger` 或任何跨 client/server 共用的 callback 之前，先假設「這段程式碼可能在任何內部事件處理中被觸發」，再決定能不能安全呼叫某個 API。


階段 A — TCP 連線洪水(建立即斷,衝擊 accept 迴圈)
階段 B — 半開/慢速連線(佔住連線槽,connect 後不送 Hello,不關)
階段 C — OPC UA Hello/SecureChannel 洪水(送半個合法握手就停,逼 server 分配 channel 資源)

T1 — aggregation_server(先起)


./aggregation_server 2>&1 | awk '{print strftime("[%H:%M:%S]"),$0; fflush()}' | tee agg.log
T2 — sensor_pub


./sensor_pub 2>&1 | awk '{print strftime("[%H:%M:%S]"),$0; fflush()}' | tee sensor.log
T3 — motor_sub(需要 GPIO,没有硬体可跳过)


./motor_sub 2>&1 | awk '{print strftime("[%H:%M:%S]"),$0; fflush()}' | tee motor.log
T4 — Anomaly_client


./Anomaly_client 2>&1 | awk '{print strftime("[%H:%M:%S]"),$0; fflush()}' | tee anomaly.log

sudo tcpdump -i any -w B_$(date +%H%M%S).pcap \
  'tcp port 4840 or tcp port 4842 or tcp port 4801 or udp port 4843'

階段 A — TCP 連線洪水(建立即斷,衝擊 accept 迴圈)
階段 B — 半開/慢速連線(佔住連線槽,connect 後不送 Hello,不關)
階段 C — OPC UA Hello/SecureChannel 洪水(送半個合法握手就停,逼 server 分配 channel 資源)

### 階段A
python3 dos_flood.py A --conns 5  --rate 5  --dur 15 --port 4842
python3 dos_flood.py A --conns 20 --rate 20 --dur 15 --port 4842
python3 dos_flood.py A --conns 50 --rate 50 --dur 20 --port 4842


### 階段B
python3 dos_flood.py B --conns 20  --dur 30 --port 4842   # 轻:占 20 条
python3 dos_flood.py B --conns 50  --dur 30 --port 4842   # 中:逼近预设上限
python3 dos_flood.py B --conns 100 --dur 40 --port 4842   # 重:远超上限

### 階段C  
原理:每条连线送一个合法的 OPC UA Hello (HELF) 讯息后停住,逼 server 真的走进 OPC UA 协定栈、分配 SecureChannel 资源。比阶段 B 更深入 —— B 只占 TCP 层,C 逼 server 分配应用层资源。


python3 dos_flood.py C --conns 20 --rate 10 --dur 20 --port 4842   # 轻
python3 dos_flood.py C --conns 40 --rate 20 --dur 20 --port 4842   # 中
python3 dos_flood.py C --conns 60 --rate 30 --dur 30 --port 4842   # 重