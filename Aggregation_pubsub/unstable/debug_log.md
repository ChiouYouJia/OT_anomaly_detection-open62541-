# Aggregation PubSub 除錯報告

專案：`aggregation_server.c` / `sensor_pub.c` / `motor_sub.c` / `Anomaly_client.c`（open62541 OPC UA + PubSub）

---

## 問題 1：log 出現 `%u` `%s` 樣板文字沒被展開

**現象**：`motor_sub.c` / `sensor_pub.c` 的 `customLogger` 印出的 network/channel 類 log，`%u`、`%s` 沒有被替換成實際數值。

**根因**：`customLogger` 只有 `UA_LOGCATEGORY_USERLAND` 分類會用 `vsnprintf(msg, args)` 展開參數，其餘分類直接把格式字串本身塞進 `%s`，`args` 完全沒被消費。

**修法**：不分類別，先用 `vsnprintf(rendered, msg, args)` 展開一次，再包 `[System]` 前綴。

**狀態**：✅ 已解決並確認。

---

## 問題 2：Aggregation Server 連不上 sensor_pub（BadTimeout）

**現象**：`aggregation_server.c` 連線到 sensor_pub（port 4842）的 client 一直 `BadTimeout`，從未印出「成功連線到底層 Sensor」，`AggregatedDistance` 從未真正被更新。

**根因**：`sensorClientConfig->timeout` 被設成 100ms，OPC UA 完整握手（TCP connect + OpenSecureChannel + CreateSession + ActivateSession）在 100ms 內做不完。

**修法**：timeout 從 100ms 調整為 2000ms。

**狀態**：⚠️ 這個改動單獨無法解決問題，因為根因其實是問題 3（log callback 阻塞了 handshake）。兩個修法一起生效後才真正解決。

---

## 問題 3：motor_sub / sensor_pub segfault，且 Aggregation Server 依然連不上

**現象**：
- 兩支程式在連上 Aggregation Server 之後很快 segfault。
- Aggregation Server 端可觀察到 `SecureChannel created` 到握手完成之間，有一段接近逾時值的延遲（幾乎精準卡在 timeout 值上）。

**根因**：`customLogger` 同時被裝在 server 的 logger 和 syslog client 的 logger 上。當 server 內部事件（例如接受一個新連線）觸發 log，`customLogger` 又回頭同步呼叫 `syslogClient` 的 `UA_Client_getState` / `UA_Client_writeValueAttribute`（阻塞的網路呼叫）。這造成：
1. Server 正在處理的 handshake 被這個阻塞呼叫卡住，导致對方逾時。
2. 在同一個呼叫堆疊裡重入同一個 client/server 物件的內部狀態機，屬於 open62541 不保證安全的情境，直接導致 segfault。

**修法**：徹底重構 `customLogger`，讓它**只負責把訊息排進一個固定大小的環狀佇列**（`enqueue_log`），不呼叫任何 `UA_Client_*` API。真正送出（`flush_log_queue_once`）改到主迴圈裡呼叫，每個 tick 最多送一筆，並在偵測到斷線時清空佇列（`clear_log_queue`）避免補送過期訊息。

**狀態**：✅ 已解決。Aggregation Server 之後能穩定連上 sensor_pub、建立 Subscription 並持續運作。

---

## 問題 4：新的 segfault —— open62541 PUBSUB log 的 heap-buffer-overflow

**現象**：問題 3 修好後，motor_sub / sensor_pub 又在不同情境下 segfault。用 AddressSanitizer 編譯後抓到：

```
AddressSanitizer: heap-buffer-overflow ... in printf_common
#2 customLogger ...
#3 (libopen62541.so)
#4 UA_ReaderGroup_setPubSubState / UA_DataSetWriter_setPubSubState
```

**根因**：open62541 1.5.x 在組 ReaderGroup / DataSetWriter 狀態轉換的 log 訊息時，內部用 `%s` 直接印一個由 `UA_String_fromChars` 配置、但**沒有 null terminator** 的 `UA_String.data`（很可能是元件名稱如 `rgConfig.name`／`dswConfig.name`）。這是 open62541 library 內部的 bug：`UA_String` 是長度前綴字串，本來就不保證 null-terminated，用 `%s` 格式化它本身就不安全，只是在沒人真正呼叫 `vsnprintf` 消費這些 args 之前，這個 bug 從未被觸發過（也就是問題 1 修好之後才「順便」暴露出來）。

**修法**：`customLogger` 對 `UA_LOGCATEGORY_PUBSUB` 分類特別處理——不呼叫 `vsnprintf` 展開參數，直接印原始格式字串（`snprintf(rendered, "%s", msg)`），犧牲這類 log 的可讀性（會看到 `%S%s -> %s%.0s` 這種殘留符號）換取不崩潰。其餘分類維持正常展開。

**狀態**：⚠️ 當時「用不展開 PUBSUB 參數」擋掉了崩潰，但**根因診斷是錯的**，見下面問題 6 的更正。

**⚠️ 後續更正（問題 6）**：真正會爆的符號是 open62541 的**非標準 `%S`**（UA_String 自訂符號），不是 `%s`+沒有 null terminator。只 guard PUBSUB 類別治標不治本——`SECURECHANNEL` 的 OpenSecureChannel 訊息也含 `%S`，之後照樣 crash。正解是改用 open62541 自家的 `UA_String_vformat`（見問題 6），PUBSUB 特例已被移除。

---

## 問題 5：sensor_pub 廣播被拖成 3 秒 + 4842 每 2 秒殭屍連線（兩個症狀同一根因：雙向阻塞死鎖）

**現象**：
- `sensor_pub.c` 用 `UA_Server_addRepeatedCallback(..., 1000, ...)` 設 1 秒排程，實測 `[Sensor] 📡 廣播並更新距離` 常常變成 **3 秒**一次。
- `sensor_pub` 的 4842 上有一條連線**每 2 秒穩定開又關**（`TCP 17 | server socket 9`），來源不明。
- `aggregation_server` 對 4842 的 client 反覆 **BadTimeout**（剛好卡在 2000ms），`AggregatedDistance` 從未真正更新（等於問題 2 又回來了）。

**誤判與更正**：`debug_log`/`claude.md` 原本推測是「主迴圈 `UA_Server_run_iterate(server, 0)` 的 0ms 逾時害排程不準」，並打算把 `0` 改成 `10`。**這是錯的**，實測資料推翻：主迴圈本來就每輪 `usleep(10000)`，`run_iterate` 早就每 ~10ms 被叫一次，timer 精度沒問題；而且 `aggregation_server` 早就用 `run_iterate(server, 10)` 卻照樣壞。3 秒的空窗代表「主迴圈被某個**阻塞呼叫**卡了 ~2 秒」，不是 timer 精度。

**根因（用 `lsof -i :4842` 現場確認 + 對時間軸）**：4842 上的殭屍連線就是 **aggregation_server 自己的 sensorClient**（timeout=2000ms）。兩個 server 在各自主迴圈裡對彼此做**阻塞式** client 呼叫，互相 head-of-line block：
1. `aggregation` 主迴圈跑阻塞式 `UA_Client_connect(→sensor:4842)`，一卡 2 秒；期間它的 server@4840 停止回應。
2. `sensor` 主迴圈 `flush_log_queue_once()` 跑阻塞式 `UA_Client_writeValueAttribute(→aggregation:4840)`；因 4840 沒在轉而卡住，期間 sensor 的 server@4842 停止回應。
3. sensor@4842 停擺 → aggregation 對 4842 的握手（CreateSession）拿不到回應 → 卡到 2000ms 逾時。
4. 逾時那刻 aggregation 恢復 → 4840 恢復 → sensor 的 write 解鎖 → 補跑早該觸發的廣播。整個循環被 aggregation 的「3 秒重連 gate」節流成 3 秒一輪。

**修法**：`aggregation_server.c` 對 4842 改用**非阻塞**的 `UA_Client_connectAsync` + 一個小狀態機（phase 0 未連 / 1 async 握手中 / 2 已訂閱），每輪 `UA_Client_run_iterate` 推進握手，Session `ACTIVATED` 後才建訂閱。主迴圈不再被阻塞 → 死鎖鏈斷開。

**狀態**：✅ 已解決。廣播回穩 1 秒、殭屍連線消失、`AggregatedDistance` 正常更新。（原「待查」的 3 秒排程與 2 秒連線兩件事，都由此一併結案。）

---

## 問題 6：`%S` 寬字元 SEGV（問題 5 解開後才浮現，同時更正問題 4）

**現象**：問題 5 修好後（握手終於能完整跑完），`sensor_pub_asan` 在處理 OpenSecureChannel 的 log 時 SEGV：
```
AddressSanitizer: SEGV in __wcsnlen_avx2  ←  寬字元路徑
  __wcsrtombs → vfprintf-internal → vsnprintf → customLogger (sensor_pub.c)
  ← Service_OpenSecureChannel ← UA_Server_run_iterate
```

**根因**：open62541 的 log 格式字串用的是「`UA_String_format` 的規則」，比 C 標準多了 `%S`(UA_String)、`%N`(UA_NodeId)、`%Q`(QualifiedName) 等**自訂符號**（見 `plugin/log.h` 註解）。直接丟給 glibc 的 `vsnprintf`，`%S` 會被當成 C 標準的**寬字元字串 `wchar_t*`**，glibc 於是拿下一個 vararg（其實是 `UA_String`）當寬字串指標去 `wcsnlen`/`wcsrtombs` → 讀亂數位址 → SEGV。**與類別無關**（PUBSUB、SECURECHANNEL 都會中）——這也更正了問題 4「以為是 `%s`+沒 null terminator」的誤判：真正的兇手一直是 `%S`。之前不 crash，只是因為問題 5 的死鎖讓握手跑不完、那行 `%S` log 沒機會被印。

**修法**：`customLogger` 不再自己 `vsnprintf`，改用 open62541 自家的 va_list 版格式化器 **`UA_String_vformat(&out, msg, args)`**（就是內建 `UA_Log_Stdout` 用的同一支），能正確把 `%S`/`%N`/`%Q` 展開成**可讀的真實值**（不崩潰、也不是殘留模板）。它只做字串格式化、不碰任何 client/server 狀態，從 logger 呼叫是安全的（不違反「logger 不可呼叫 `UA_Client_*`」）。問題 4 的 PUBSUB 特例已被移除。

**狀態**：✅ 已解決。system log 恢復顯示真實值（如 SecurityPolicy 完整 URL、Session 真實 GUID），不再 crash、不再模板。

---

## 問題 7（功能強化）：CentralLog 單值節點會漏接 log，且晚連的 Anomaly 補不到歷史

**現象**：`CentralLog` 原本是單一 scalar String，三支程式都 `writeValueAttribute` 覆蓋它。`Anomaly_client` 晚幾十秒才連上時，連上前的 system log 早被後續寫入蓋掉，看起來「system log 傳不到 Anomaly」。客戶端就算把 `samplingInterval=0`、`queueSize=1000` 調到極限也救不回——單值節點永遠只保留最新那一行。

**修法（伺服器端資料模型改成環狀陣列）**：
- 新增 scalar String 節點 `CentralLogIn` 當**寫入口**；三支 writer 改寫這裡（僅一行 node id 變更，邏輯不動）。
- `CentralLog` 改成 **String 陣列 ring buffer**（唯讀，保留最近 `CLOG_RING_CAP=256` 行），`Anomaly` 訂閱它。
- `CentralLogIn` 掛 `onWrite` value callback：把新行 append 進 ring buffer（附**單調遞增序號前綴** `#<seq> ` 供去重）並標記 dirty；**主迴圈**才整包寫回 `CentralLog` 陣列（刻意 append 與 writeValue 分離，不在 callback 裡呼叫 `UA_Server_writeValue`，避免重入寫入服務）。
- `Anomaly_client` 的 handler 改吃陣列、用 `seq` 去重：一連上就收到整包 buffer（**補歷史**），之後每次拿最新快照挑出沒看過的新行。就算取樣把多次寫入合併成一次，快照本身含完整歷史（最多 256 行），故**不漏接**。

**狀態**：✅ 已驗證（故意讓 Anomaly 晚 8 秒才連）：補得到連線前的 `[System]` 歷史、即時串流不中斷、無重複、無 crash。異常偵測邏輯掛在 `Anomaly_client.c` handler 內標了 `👉` 的那行（純文字 `msg_ptr`/`msg_len` + `seq`）。

**已知取捨**：`last_seq` 跨 client 重連保持單調；若「aggregation_server 本身」重啟（seq 歸零），需一併重啟 `Anomaly_client`。關機時 subscriber 會噴約 10 行 `PublishResponse: Received response for an unknown Subscription`——那是在飛的 PublishRequest 撞上已清掉的本地訂閱狀態的收尾競態，**無害**。

---

## 修改檔案清單（累積的變更）

**第一輪（問題 1–4）**
- `aggregation_server.c`：`sensorClientConfig->timeout` 100ms → 2000ms
- `motor_sub.c` / `sensor_pub.c`：
  - `customLogger` 統一展開非 USERLAND 類別的 log（修問題 1）
  - 移除 `is_sending_log` 旗標，改為 log queue（`enqueue_log` / `flush_log_queue_once` / `clear_log_queue`），logger 不再呼叫任何 `UA_Client_*` API（修問題 3）
  - 新增簡單的重複行抑制（連續超過 3 次相同訊息會被吃掉）
  - ~~`UA_LOGCATEGORY_PUBSUB` 例外，不展開參數（修問題 4）~~ → 已被下面問題 6 的 `UA_String_vformat` 取代

**第二輪（問題 5–7，本次）**
- `aggregation_server.c`：
  - 對 4842 的 client 改用 `UA_Client_connectAsync` + 狀態機（phase 0/1/2），主迴圈不再阻塞（修問題 5 死鎖）
  - `CentralLog` 改成 String 陣列 ring buffer；新增 `CentralLogIn` scalar 寫入口 + `onWrite` callback；新增 `central_log_append` / `central_log_publish` 環狀緩衝邏輯（修問題 7）
- `sensor_pub.c` / `motor_sub.c`：
  - `customLogger` 改用 `UA_String_vformat` 展開（正確處理 `%S`/`%N`/`%Q`，移除 PUBSUB 特例）（修問題 6）
  - log 寫入目標 `CentralLog` → `CentralLogIn`（配合問題 7）
- `Anomaly_client.c`：訂閱的 `CentralLog` 現在是陣列，handler 改吃 `String[]` + 用 `#<seq>` 前綴去重（配合問題 7）

## 建置注意（本機 pkg-config 地雷）

這台機器 `pkg-config --libs open62541` 會把 mbedtls 輸出成壞格式的 `-l/絕對路徑.so`，直接用會連結失敗（`cannot find -l/usr/lib/.../libmbedtls.so`）。改成直接帶 `.so` 路徑：

```bash
MBED="/usr/lib/x86_64-linux-gnu/libmbedtls.so /usr/lib/x86_64-linux-gnu/libmbedx509.so /usr/lib/x86_64-linux-gnu/libmbedcrypto.so"
CF="$(pkg-config --cflags open62541)"; BASE="-L/usr/local/lib -lopen62541 -lpthread -lm -lrt $MBED"
gcc -o aggregation_server aggregation_server.c $CF $BASE
gcc -o sensor_pub sensor_pub.c $CF $BASE
gcc -o motor_sub  motor_sub.c  $CF $BASE -llgpio
gcc -o Anomaly_client Anomaly_client.c $CF $BASE
# ASan 版：加 -g -O0 -fsanitize=address
```