#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>

UA_Boolean running = true;
UA_Server *server = NULL;
UA_NodeId aggDistanceNodeId;

static void stopHandler(int sig) { running = false; }

static void sensorDataChangeHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                                    UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    if(UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DOUBLE])) {
        UA_Double dist = *(UA_Double*)value->value.data;
        UA_Variant outVal;
        UA_Variant_setScalar(&outVal, &dist, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, aggDistanceNodeId, outVal);
    }
}

// ===== CentralLog 環狀緩衝區（ring buffer）=====
// 目的：讓 Anomaly_client 不漏接 log，且晚連上也能補到最近的歷史。
// 流程：sensor/motor 把單行 log 寫進 scalar 節點 CentralLogIn → onWrite callback
// 只把該行 append 進這個 ring buffer（快、不碰網路）並標記 dirty；主迴圈再把整個
// buffer 整包寫回 String 陣列節點 CentralLog（唯讀）。Anomaly 訂閱 CentralLog：
//   - 一連上就收到整包 buffer（= 最近 CLOG_RING_CAP 行歷史）
//   - 之後每次通知拿到最新快照；就算取樣把多次寫入合併成一次，快照本身就含完整
//     歷史（最多 CAP 行），故不漏接。
// 每行前綴 "#<seq> "，seq 為全域單調遞增序號，供消費端去重（只處理較大的 seq）。
// 註：append 只在 server callback context、publish 只在 main() 迴圈，皆單執行緒，無 race。
// 刻意「append 與 writeValue 分離」：不在 onWrite callback 裡呼叫 UA_Server_writeValue，
// 避免在寫入服務的呼叫堆疊中重入 server 寫入機制（延續本專案 callback 不做重活的原則）。
#define CLOG_RING_CAP  256
// 1536(client 端 full_log 上限，含 LogRecord 欄位) + SourceNode 後綴 + 序號前綴的餘裕
#define CLOG_LINE_MAX  1792
static char       clog_ring[CLOG_RING_CAP][CLOG_LINE_MAX];
static size_t     clog_count = 0;      // buffer 內有效行數（<= CAP）
static size_t     clog_head  = 0;      // 下一個寫入位置（環狀）
static uint64_t   clog_seq   = 0;      // 全域序號
static UA_Boolean clog_dirty = false;  // 有新行待整包寫回 CentralLog

static void central_log_append(const char *line) {
    clog_seq++;
    snprintf(clog_ring[clog_head], CLOG_LINE_MAX, "#%llu %s",
             (unsigned long long)clog_seq, line);
    clog_head = (clog_head + 1) % CLOG_RING_CAP;
    if (clog_count < CLOG_RING_CAP) clog_count++;
    clog_dirty = true;
}

// 只從 main() 迴圈呼叫：若有新行，依時間順序（最舊→最新）整包寫回 CentralLog 陣列。
static void central_log_publish(void) {
    if (!clog_dirty) return;
    clog_dirty = false;

    UA_String arr[CLOG_RING_CAP];
    size_t start = (clog_count < CLOG_RING_CAP) ? 0 : clog_head; // 最舊那筆的位置
    for (size_t i = 0; i < clog_count; i++)
        arr[i] = UA_STRING(clog_ring[(start + i) % CLOG_RING_CAP]);

    UA_Variant v;
    UA_Variant_setArray(&v, arr, clog_count, &UA_TYPES[UA_TYPES_STRING]);
    // writeValue 會深拷貝 v 的內容進節點，回傳後 arr（指向 clog_ring）即可丟棄。
    UA_Server_writeValue(server, UA_NODEID_STRING(1, "CentralLog"), v);
}

// ===== OPC UA Part 22 LogRecord：SourceNode 來源歸屬（防 R 否認攻擊）=====
// 規範 Table 8 定義了 SourceNode (0:NodeId)「這筆記錄來自哪個 Node」。先前實作
// 未填此欄位，導致 log 無法歸屬來源 → 否認(R)攻擊在原理上無法從 log 偵測
// （見 ml/EXPERIMENTS.md 消融實驗：三個 ML 模型的真實 R recall 都是 0%）。
//
// 關鍵設計：SourceNode 必須由「伺服器端」蓋章，不能讓寫入者自己填。
//   攻擊者能偽造 log 行裡的任何文字（repudiation_attack.c 就是逐字複製 motor 的
//   輸出格式），所以若 SourceNode 只是行內的一個文字欄位，照抄即可繞過。
//   但攻擊者無法偽造「自己是誰連上來的」—— session 身分由 server 在
//   CreateSession/ActivateSession 時建立，寫入端無從竄改。
//
// 因此這裡從 sessionId 取出 server 自己記錄的 0:sessionName，據此蓋章：
//   sensor_pub / motor_sub  → 具名 session ("SensorSource"/"MotorSource")
//                             → SourceNode=ns=1;s=<Name>  (已驗證)
//   匿名或未知的 session     → SourceNode=null            (未驗證)
// 攻擊者以匿名連線注入的偽造 motor log 會被蓋上 SourceNode=null，
// 與真 motor 的 ns=1;s=MotorSource 明確可分 → R 變成可偵測。
//
// 對映到規範：SourceNode 為 Optional=True，「若記錄不屬於特定 Node 則設為 null
// NodeId」。匿名寫入者確實不對應任何已知 Node，填 null 完全符合規範語意。

// 已授權的來源：session 名稱 → 該來源的 SourceNode / SourceName。
// 註：本專案為研究環境，以 session 名稱作為身分。正式部署應改用憑證/使用者
// 認證（AccessControl plugin），此表則改為「憑證主體 → SourceNode」的對映。
// 1 sensor + N motor 拓撲：每台 motor 以不同 session 名註冊，才能在 log 上
// 分辨「是哪一台 motor 寫的」。未列在此表的 session（含匿名攻擊者）→ "null"。
//
// ⚠️ 為什麼不再用寫死的表：舊版只列 MotorSource / MotorSource2 / MotorSource3，
//    第 4 台以後的 motor 會被判成 SourceNode=null → 整份資料的標籤被污染
//    （null 規則會把所有正常 motor 寫入標成攻擊）。要把拓撲做大就必須解除。
//
// 動態化的方式仍**保持封閉世界**（不是「凡是叫 MotorSourceX 都放行」）：
//    合法身分 = SensorSource ∪ { MotorSource, MotorSource2 .. MotorSourceN }
//    N 由環境變數 AGG_N_MOTOR 指定（預設 3），採集腳本會傳入實際 motor 台數。
//    這一點很重要：若改成任意數字都接受，攻擊者只要把 session 名取成
//    MotorSource99 就能自己蓋出具名 SourceNode，等於廢掉 R/S/RP 的偵測前提。
//    上限也順便防住「用超大編號洗掉歸屬」的濫用。
#define AGG_MAX_MOTOR 256
static int agg_n_motor = 3;                  // 由 read_n_motor_env() 於啟動時設定
static int agg_n_sensor = 1;                 // 同上，環境變數 AGG_N_SENSOR

static void read_n_motor_env(void) {
    const char *e = getenv("AGG_N_MOTOR");
    if (e && *e) {
        char *end = NULL;
        long v = strtol(e, &end, 10);
        if (end && *end == '\0' && v >= 1 && v <= AGG_MAX_MOTOR)
            agg_n_motor = (int)v;
        else
            fprintf(stderr, "[agg] AGG_N_MOTOR=%s 無效（需 1..%d），沿用 %d\n",
                    e, AGG_MAX_MOTOR, agg_n_motor);
    }
    const char *es = getenv("AGG_N_SENSOR");
    if (es && *es) {
        char *end = NULL;
        long v = strtol(es, &end, 10);
        if (end && *end == '\0' && v >= 1 && v <= AGG_MAX_MOTOR)
            agg_n_sensor = (int)v;
        else
            fprintf(stderr, "[agg] AGG_N_SENSOR=%s 無效（需 1..%d），沿用 %d\n",
                    es, AGG_MAX_MOTOR, agg_n_sensor);
    }
}

// 依 session 身分解析出 SourceNode 字串；無法歸屬時填 "null"。
// 由呼叫端提供緩衝區（名稱是動態產生的，不能回傳指向區域變數的指標）。
static void resolve_source_node(UA_Server *s, const UA_NodeId *sessionId,
                                char *outNode, size_t outLen) {
    snprintf(outNode, outLen, "null");
    if (sessionId == NULL) return;            // 非 session 觸發（如伺服器自身寫入）

    UA_String sessionName = UA_STRING_NULL;
    UA_StatusCode rc = UA_Server_getSessionAttribute_scalar(
        s, sessionId, UA_QUALIFIEDNAME(0, "sessionName"),
        &UA_TYPES[UA_TYPES_STRING], &sessionName);
    if (rc != UA_STATUSCODE_GOOD || sessionName.length == 0) return;

    char name[64];
    if (sessionName.length >= sizeof(name)) return;   // 過長 → 不可能是合法身分
    memcpy(name, sessionName.data, sessionName.length);
    name[sessionName.length] = '\0';

    if (strcmp(name, "SensorSource") == 0) {
        snprintf(outNode, outLen, "ns=1;s=SensorSource");
        return;
    }
    // 多 sensor 拓撲：SensorSource2..N（同樣是封閉世界，上限由 AGG_N_SENSOR 指定）
    if (strncmp(name, "SensorSource", 12) == 0) {
        const char *snum = name + 12;
        int ok = (*snum != '\0');
        for (const char *p = snum; *p; p++)
            if (*p < '0' || *p > '9') { ok = 0; break; }
        if (ok) {
            long sidx = strtol(snum, NULL, 10);
            if (sidx >= 2 && sidx <= agg_n_sensor)
                snprintf(outNode, outLen, "ns=1;s=SensorSource%ld", sidx);
        }
        return;
    }
    if (strcmp(name, "MotorSource") == 0) {           // motor 1（沿用原名，向後相容）
        snprintf(outNode, outLen, "ns=1;s=MotorSource");
        return;
    }
    if (strncmp(name, "MotorSource", 11) == 0) {
        const char *num = name + 11;
        if (*num == '\0') return;
        for (const char *p = num; *p; p++)
            if (*p < '0' || *p > '9') return;         // 只接受純數字後綴
        long idx = strtol(num, NULL, 10);
        if (idx >= 2 && idx <= agg_n_motor)           // 封閉世界：不得超過實際台數
            snprintf(outNode, outLen, "ns=1;s=MotorSource%ld", idx);
    }
    // 其餘（含匿名攻擊者、編號超出範圍者）維持 "null"
}

// CentralLogIn 被寫入時觸發（含遠端 client 寫入）：
// 取出該行、由伺服器蓋上 SourceNode，再 append 進 ring buffer。
static void centralLogInOnWrite(UA_Server *s, const UA_NodeId *sessionId, void *sessionCtx,
                                const UA_NodeId *nodeId, void *nodeCtx,
                                const UA_NumericRange *range, const UA_DataValue *data) {
    if (!data->hasValue) return;
    if (!UA_Variant_hasScalarType(&data->value, &UA_TYPES[UA_TYPES_STRING])) return;
    const UA_String *in = (const UA_String *)data->value.data;

    // 伺服器端蓋章：附加 SourceNode 欄位。寫入者無法影響此值。
    // 若該行已自帶 "| SourceNode=" （偽造嘗試），伺服器的值仍附加在最後，
    // 且 parser 以「最後一個」為準 → 偽造無效。
    char srcNode[96];
    resolve_source_node(s, sessionId, srcNode, sizeof(srcNode));

    // 關鍵：先為 SourceNode 後綴保留空間，再截斷訊息本體。
    // 若反過來（先填滿訊息再附加），過長的行會把 SourceNode 擠掉 →
    // 攻擊者只要送超長 log 就能讓自己的來源標記消失，等於繞過歸屬機制。
    char suffix[128];
    int suffix_len = snprintf(suffix, sizeof(suffix), " | SourceNode=%s", srcNode);
    if (suffix_len < 0) return;
    if ((size_t)suffix_len >= sizeof(suffix)) suffix_len = (int)sizeof(suffix) - 1;

    char stamped[CLOG_LINE_MAX];
    size_t room = sizeof(stamped) - (size_t)suffix_len - 1;   // 留給訊息本體
    size_t n = in->length;
    if (n > room) n = room;                                   // 必要時截斷訊息，不截斷來源
    memcpy(stamped, in->data, n);
    memcpy(stamped + n, suffix, (size_t)suffix_len);
    stamped[n + (size_t)suffix_len] = '\0';

    central_log_append(stamped);
}

int main() {
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);
    read_n_motor_env();          // 合法 motor 身分上限（見 SOURCE_REGISTRY 說明）
    printf("[agg] 授權來源：SensorSource1..%d + MotorSource1..%d\n",
           agg_n_sensor, agg_n_motor);

    server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    // CentralLog：String 陣列 ring buffer（唯讀），Anomaly_client 訂閱這個節點。
    // 初始為空陣列；內容由下面 CentralLogIn 的 onWrite callback + 主迴圈維護。
    UA_VariableAttributes logAttr = UA_VariableAttributes_default;
    UA_Variant_setArray(&logAttr.value, NULL, 0, &UA_TYPES[UA_TYPES_STRING]);
    logAttr.valueRank = UA_VALUERANK_ONE_DIMENSION;
    UA_UInt32 logArrayDims = 0;                 // 一維、長度不固定
    logAttr.arrayDimensions = &logArrayDims;
    logAttr.arrayDimensionsSize = 1;
    logAttr.displayName = UA_LOCALIZEDTEXT("en-US", "CentralLog");
    logAttr.description = UA_LOCALIZEDTEXT("en-US", "Ring buffer of recent log lines (String[]), each prefixed with #<seq>");
    logAttr.accessLevel = UA_ACCESSLEVELMASK_READ;
    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "CentralLog"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, "CentralLog"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), logAttr, NULL, NULL);

    // CentralLogIn：scalar String 寫入口。sensor/motor 把每行 log 寫進這裡，
    // onWrite callback 會把它 append 進 ring buffer（見上面 centralLogInOnWrite）。
    UA_VariableAttributes logInAttr = UA_VariableAttributes_default;
    UA_String initIn = UA_STRING("");
    UA_Variant_setScalar(&logInAttr.value, &initIn, &UA_TYPES[UA_TYPES_STRING]);
    logInAttr.displayName = UA_LOCALIZEDTEXT("en-US", "CentralLogIn");
    logInAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "CentralLogIn"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, "CentralLogIn"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), logInAttr, NULL, NULL);
    UA_ValueCallback logInCb;
    logInCb.onRead = NULL;
    logInCb.onWrite = centralLogInOnWrite;
    UA_Server_setVariableNode_valueCallback(server, UA_NODEID_STRING(1, "CentralLogIn"), logInCb);

    UA_VariableAttributes distAttr = UA_VariableAttributes_default;
    UA_Double initDist = 0.0;
    UA_Variant_setScalar(&distAttr.value, &initDist, &UA_TYPES[UA_TYPES_DOUBLE]);
    distAttr.displayName = UA_LOCALIZEDTEXT("en-US", "AggregatedDistance");
    distAttr.accessLevel = UA_ACCESSLEVELMASK_READ;
    aggDistanceNodeId = UA_NODEID_STRING(1, "AggregatedDistance");
    UA_Server_addVariableNode(server, aggDistanceNodeId,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, "AggregatedDistance"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), distAttr, NULL, NULL);

    UA_Server_run_startup(server);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Aggregation Server started (port 4840)");

    UA_Client *sensorClient = UA_Client_new();
    UA_ClientConfig *sensorClientConfig = UA_Client_getConfig(sensorClient);
    UA_ClientConfig_setDefault(sensorClientConfig);
    
    // 💡 逾時調整為 2000ms：100ms 太短，連 OpenSecureChannel+CreateSession+ActivateSession
    // 三個來回都做不完，導致永遠連不上 Sensor（見 log 裡的 BadTimeout）。
    // 2000ms 仍遠低於預設的 5000ms，單次卡頓可接受，但握手有機會真正完成。
    sensorClientConfig->timeout = 2000; 

    // 連線狀態機：0 = 尚未連線, 1 = async 握手進行中, 2 = 已訂閱
    // ⚠️ 血淚教訓：這裡「絕對不能」用阻塞版 UA_Client_connect。
    // 它會把主迴圈卡住長達 timeout(2s)，期間本機 server@4840 停止回應，
    // 害得 sensor_pub 的 log 上報(writeValueAttribute→4840)也跟著阻塞，
    // 反過來 sensor 的 server@4842 停擺 → 本 client 對 4842 的握手拿不到回應
    // → 卡到逾時。兩個 server 互相 head-of-line block，症狀是：
    //   (a) sensor_pub 廣播從 1 秒被拖成 3 秒
    //   (b) 4842 上出現「每 2 秒(=timeout) 開關一次」的殭屍連線、AggregatedDistance 永遠不更新
    // 改用非阻塞的 connectAsync + 每輪 UA_Client_run_iterate 推進握手，即可斷開互鎖。
    int sensorPhase = 0;
    time_t last_try = 0;

    while(running) {
        UA_Server_run_iterate(server, 10);
        central_log_publish();   // 有新 log 就整包寫回 CentralLog 陣列（去耦合，不在 callback 裡做）

        if (sensorPhase == 0) {
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                // 💡 使用 127.0.0.1 避開 DNS 查詢地雷；connectAsync 立刻返回，不阻塞主迴圈
                UA_Client_connectAsync(sensorClient, "opc.tcp://127.0.0.1:4842");
                sensorPhase = 1;
            }
        } else {
            // 每輪都要 iterate，async 握手與訂閱回呼才會往前推進
            UA_Client_run_iterate(sensorClient, 0);
            UA_SecureChannelState channelState; UA_SessionState sessionState; UA_StatusCode connectStatus;
            UA_Client_getState(sensorClient, &channelState, &sessionState, &connectStatus);

            // Session 真正 activated 後才建立訂閱（只建一次）
            if (sensorPhase == 1 && sessionState == UA_SESSIONSTATE_ACTIVATED) {
                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Connected to sensor backend; starting data aggregation");
                UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
                UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(sensorClient, request, NULL, NULL, NULL);
                UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "DistanceValue"));
                UA_Client_MonitoredItems_createDataChange(sensorClient, response.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, monRequest, NULL, sensorDataChangeHandler, NULL);
                sensorPhase = 2;
            }

            if (sensorPhase == 2 && channelState == UA_SECURECHANNELSTATE_CLOSED) {
                // 已建立的連線斷掉 → 回背景重連
                UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Sensor connection lost; switching to background reconnect mode");
                UA_Client_disconnect(sensorClient);
                sensorPhase = 0;
            } else if (sensorPhase == 1 && time(NULL) - last_try >= 3) {
                // 3 秒內握手仍未 activated（用 wall-clock 判定，避開剛發起時 channelState 短暫為 CLOSED 的競態）
                // → 放棄這次握手、收乾淨，下一輪重試
                UA_Client_disconnect(sensorClient);
                sensorPhase = 0;
            }
        }
    }

    UA_Server_run_shutdown(server);
    UA_Client_disconnect(sensorClient); UA_Client_delete(sensorClient); UA_Server_delete(server);
    return 0;
}