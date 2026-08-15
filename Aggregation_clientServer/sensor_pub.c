#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>

// 💡 Client/Server 版：sensor 不再用 PubSub 廣播距離。它只當一台 OPC UA
// Server（@4842），把量到的距離寫進 DistanceValue 節點；motor 與
// aggregation_server 各自以 client 連過來訂閱這個節點（見 motor_sub.c /
// aggregation_server.c）。原本的 UDP multicast PubSub 設定已全部移除。

UA_Boolean running = true;
UA_Boolean syslog_connected = false;

// ---- 多 sensor 實例（項目 2：拓撲放大，見 net/TOPO_SCALEUP_DESIGN.md）----
// 不帶參數 → sensor_id=1、port 4842、sessionName "SensorSource"，與改造前完全一致
// （既有腳本與既有採集資料不受影響）。
//   sensor_id i → port 4841+i、sessionName "SensorSource<i>"（i=1 沿用原名）
// ⚠️ 各 sensor 的量測值刻意用**相同值域、不同亂數序列**：
//    若改成不同值域，光看「這個值落在哪個區間」就能推回它屬於哪一群 —— 那又變成
//    一個不需要圖結構的平特徵，實驗就白做了。相同值域下，「這個值對不對」只能靠
//    『它跟同一個 sensor 的那群 peer 是否一致』來判斷，而那需要拓撲。
static int  sensor_id = 1;
static char sensor_session[32] = "SensorSource";
static char sensor_srcname[32] = "Sensor";
UA_NodeId distanceNodeId;
UA_Client *syslogClient = NULL;

// 💡 關鍵重構：customLogger 絕對不可以直接呼叫 UA_Client_* 這種會阻塞、
// 會重入 client 內部狀態機的函式。之前那版在 log callback 裡呼叫
// UA_Client_getState/writeValueAttribute，一旦這個 log 剛好是在
// UA_Client_connect() 或 UA_Server_run_iterate() 內部觸發的（例如
// "SecureChannel created" 這類訊息），就等於在 client/server 還沒處理完
// 自己的狀態機時，從同一個呼叫堆疊裡回頭去戳同一個 client 物件——
// 這就是這次 segfault、以及 Aggregation Server 一直卡在 BadTimeout 的
// 真正原因：log callback 裡的同步網路呼叫，會把當下正在處理的
// SecureChannel/Session handshake卡住，卡到對方逾時。
// 修法：logger 只負責把訊息「排隊」，真正送出的動作全部移到主迴圈，
// 而且主迴圈每次最多送一筆，不會在一次事件裡連續觸發一堆阻塞呼叫。
#define LOG_QUEUE_SIZE 64
static char log_queue[LOG_QUEUE_SIZE][1536];   // 與 full_log 同寬，避免 LogRecord 欄位在排隊時被截掉
static int log_queue_head = 0;
static int log_queue_tail = 0;
static int log_queue_count = 0;

static void enqueue_log(const char *line) {
    if (log_queue_count >= LOG_QUEUE_SIZE) {
        // 佇列滿了：丟掉最舊的一筆騰出空間，優先保留最新狀態
        log_queue_tail = (log_queue_tail + 1) % LOG_QUEUE_SIZE;
        log_queue_count--;
    }
    strncpy(log_queue[log_queue_head], line, sizeof(log_queue[0]) - 1);
    log_queue[log_queue_head][sizeof(log_queue[0]) - 1] = '\0';
    log_queue_head = (log_queue_head + 1) % LOG_QUEUE_SIZE;
    log_queue_count++;
}

static void clear_log_queue(void) {
    log_queue_head = log_queue_tail = log_queue_count = 0;
}

// 只從 main() 的迴圈呼叫，絕對不要從 customLogger 裡呼叫。
static void flush_log_queue_once(void) {
    if (log_queue_count == 0) return;
    if (!(syslogClient && syslog_connected)) return;

    UA_SecureChannelState chState; UA_SessionState sessState; UA_StatusCode connStat;
    UA_Client_getState(syslogClient, &chState, &sessState, &connStat);
    if (chState != UA_SECURECHANNELSTATE_OPEN) return;

    UA_Variant val; UA_String ua_msg = UA_STRING(log_queue[log_queue_tail]);
    UA_Variant_setScalar(&val, &ua_msg, &UA_TYPES[UA_TYPES_STRING]);
    UA_Client_writeValueAttribute(syslogClient, UA_NODEID_STRING(1, "CentralLogIn"), &val);
    log_queue_tail = (log_queue_tail + 1) % LOG_QUEUE_SIZE;
    log_queue_count--;
}

static void stopHandler(int sig) { running = false; }

static void customLogger(void *logContext, UA_LogLevel level, UA_LogCategory category, const char *msg, va_list args) {
    if (category == UA_LOGCATEGORY_EVENTLOOP) return;
    if (level == UA_LOGLEVEL_TRACE || level == UA_LOGLEVEL_DEBUG) return;
    if (!syslog_connected && category != UA_LOGCATEGORY_USERLAND) return;
    if (category == UA_LOGCATEGORY_CLIENT && level == UA_LOGLEVEL_INFO) return;

    // 💡 官方巨集絕對匹配，不再出現誤判 warn
    const char *levelStr = "unknown";
    if (level == UA_LOGLEVEL_TRACE) levelStr = "trace";
    else if (level == UA_LOGLEVEL_DEBUG) levelStr = "debug";
    else if (level == UA_LOGLEVEL_INFO) levelStr = "info";
    else if (level == UA_LOGLEVEL_WARNING) levelStr = "warn";
    else if (level == UA_LOGLEVEL_ERROR) levelStr = "error";
    else if (level == UA_LOGLEVEL_FATAL) levelStr = "fatal";

    const char *catStr = "unknown";
    switch(category) {
        case UA_LOGCATEGORY_NETWORK:       catStr = "network"; break;
        case UA_LOGCATEGORY_SECURECHANNEL: catStr = "channel"; break;
        case UA_LOGCATEGORY_SESSION:       catStr = "session"; break;
        case UA_LOGCATEGORY_SERVER:        catStr = "server"; break;
        case UA_LOGCATEGORY_CLIENT:        catStr = "client"; break;
        case UA_LOGCATEGORY_USERLAND:      catStr = "application"; break;
        case UA_LOGCATEGORY_SECURITYPOLICY:catStr = "security"; break;
        case UA_LOGCATEGORY_PUBSUB:        catStr = "pubsub"; break;
        case UA_LOGCATEGORY_DISCOVERY:     catStr = "discovery"; break;
    }

    // 💡 open62541 的 log 訊息用的是「UA_String_format 的格式規則」，比 C 標準多了
    // %S(UA_String)、%N(UA_NodeId)、%Q(QualifiedName) 等自訂符號（見 plugin/log.h 註解）。
    // 直接丟給 glibc 的 vsnprintf，%S 會被當成 C 標準的「寬字元字串 wchar_t*」，於是 glibc
    // 拿下一個 vararg（其實是 UA_String）當寬字串指標去 wcsnlen/wcsrtombs → 讀亂數位址
    // → SEGV（ASan: __wcsnlen_avx2）。正解：用 open62541 自家的 va_list 版格式化器
    // UA_String_vformat 展開——它就是內建 UA_Log_Stdout 用的同一支，能正確把 %S/%N/%Q
    // 印成可讀真實值，且只做字串格式化、不碰任何 client/server 內部狀態，從 logger 呼叫安全。
    char rendered[512];
    UA_String formatted = UA_STRING_NULL;   // 零長度 → vformat 會自行 malloc 足夠空間
    va_list args_copy; va_copy(args_copy, args);
    UA_StatusCode fmtRet = UA_String_vformat(&formatted, msg, args_copy);
    va_end(args_copy);
    if (fmtRet == UA_STATUSCODE_GOOD && formatted.data != NULL) {
        // UA_String 不保證有 null terminator，一律用 %.*s 帶長度
        snprintf(rendered, sizeof(rendered), "%.*s", (int)formatted.length, (const char *)formatted.data);
    } else {
        snprintf(rendered, sizeof(rendered), "%s", msg);  // 保底：至少印原始格式字串
    }
    UA_String_clear(&formatted);            // 釋放 vformat 配置的記憶體

    char msg_buf[512];
    if (category == UA_LOGCATEGORY_USERLAND) {
        snprintf(msg_buf, sizeof(msg_buf), "%s", rendered);
    } else {
        snprintf(msg_buf, sizeof(msg_buf), "[System] %s", rendered);
    }

    // OPC UA Part 22 (Diagnostics) Table 9 - LogRecord Severity Mapping：
    // Severity 是 1-1000 的 UInt16。取各 syslog 級距的代表值。
    //   Error 201-250 / Warning 151-200 / Information 51-100 / Debug 1-50
    UA_UInt16 severity = 75;                       // Information（預設）
    if (level == UA_LOGLEVEL_FATAL)        severity = 500;  // Emergency 401-1000
    else if (level == UA_LOGLEVEL_ERROR)   severity = 225;  // Error     201-250
    else if (level == UA_LOGLEVEL_WARNING) severity = 175;  // Warning   151-200
    else if (level == UA_LOGLEVEL_INFO)    severity = 75;   // Information 51-100
    else if (level == UA_LOGLEVEL_DEBUG || level == UA_LOGLEVEL_TRACE) severity = 25; // Debug 1-50

    // SourceName (Table 8, 0:String)：來源的可讀描述。
    // 注意 SourceNode 不在這裡填 —— 它必須由 aggregation_server 依 session 身分
    // 蓋章，client 自填會被攻擊者照抄而失去意義（見 aggregation_server.c 註解）。
    const char *sourceName = (category == UA_LOGCATEGORY_USERLAND) ? sensor_srcname : "System";

    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
    char full_log[1536];   // 加大：容納 LogRecord 欄位後綴
    // 保留原有前綴（Time/level/cat/Message）以維持既有 parser 與工具相容，
    // 於行尾附加 LogRecord 欄位。SourceNode 由伺服器端追加。
    snprintf(full_log, sizeof(full_log),
             "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/%s\t%s"
             " | Severity=%u | SourceName=%s | EventType=%s",
             dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec, dts.milliSec,
             levelStr, catStr, msg_buf,
             severity, sourceName, catStr);

    // 💡 重複行抑制：斷線瞬間 open62541 內部常會在同一個 tick 裡連續吐出
    // 好幾十筆一模一樣的 log（例如 BadTimeout），這裡把超過門檻的重複行吃掉，
    // 只在訊息真的變化時，補印一行「重複 N 次」。
    static char last_msg_buf[512] = {0};
    static int dup_count = 0;
    static time_t last_msg_time = 0;
    time_t now_sec = time(NULL);
    if (strncmp(msg_buf, last_msg_buf, sizeof(last_msg_buf)) == 0 && (now_sec - last_msg_time) <= 2) {
        dup_count++;
        if (dup_count > 3) {
            return;
        }
    } else {
        if (dup_count > 3) {
            printf("[...] (previous message repeated %d more times, suppressed)\n", dup_count - 3);
        }
        dup_count = 0;
        strncpy(last_msg_buf, msg_buf, sizeof(last_msg_buf) - 1);
        last_msg_time = now_sec;
    }

    printf("%s\n", full_log);

    // 💡 只排隊，絕不在這裡呼叫任何 UA_Client_* API（見上面的說明）。
    if (syslog_connected) {
        enqueue_log(full_log);
    }
}

double read_distance(void){ return 2.0 + ((double)rand() / (RAND_MAX / (50.0 - 2.0))); }

static void updateDistanceCallback(UA_Server *server, void *data) {
    UA_Double distance = read_distance();
    UA_Variant value; UA_Variant_setScalar(&value, &distance, &UA_TYPES[UA_TYPES_DOUBLE]);
    UA_Server_writeValue(server, distanceNodeId, value);
    UA_LOG_INFO(UA_Server_getConfig(server)->logging, UA_LOGCATEGORY_USERLAND,
                "[Sensor] Updated distance: %.1f cm", distance);
}

int main(int argc, char **argv) {
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);

    if (argc > 1) {
        sensor_id = atoi(argv[1]);
        if (sensor_id < 1 || sensor_id > 64) {
            fprintf(stderr, "用法: %s [sensor_id 1..64]\n", argv[0]);
            return 1;
        }
    }
    if (sensor_id > 1) {
        snprintf(sensor_session, sizeof(sensor_session), "SensorSource%d", sensor_id);
        snprintf(sensor_srcname, sizeof(sensor_srcname), "Sensor%d", sensor_id);
    }
    // 不同實例用不同亂數種子 → 值域相同但序列獨立（見上方說明）
    srand((unsigned)time(NULL) + (unsigned)sensor_id * 7919u);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, (UA_UInt16)(4841 + sensor_id), NULL);
    config->logging->log = customLogger;

    // DistanceValue：sensor 量到的距離。motor 與 aggregation_server 以 client
    // 訂閱這個節點（client/server 傳輸，取代原本的 PubSub 廣播）。
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Double initDistance = 0.0; UA_Variant_setScalar(&attr.value, &initDistance, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "DistanceValue");
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    distanceNodeId = UA_NODEID_STRING(1, "DistanceValue");
    UA_Server_addVariableNode(server, distanceNodeId, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "Distance Sensor"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attr, NULL, NULL);

    UA_Server_addRepeatedCallback(server, (UA_ServerCallback)updateDistanceCallback, NULL, 1000, NULL);

    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND,
                "Sensor Server online (Client/Server mode, id=%d port=%d)",
                sensor_id, 4841 + sensor_id);
    UA_Server_run_startup(server);

    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    // 💡 徹底移除 timeout 猛藥
    clientConfig->logging->log = customLogger;

    // OPC UA Part 22 LogRecord / SourceNode 來源歸屬：
    // 具名 session 讓 aggregation_server 能在收到 log 時辨識來源，並由「伺服器端」
    // 蓋上 SourceNode=ns=1;s=SensorSource。攻擊者可以逐字複製 log 內容，但無法
    // 冒用這個 session 身分 —— 這正是否認(R)攻擊的防線。詳見 aggregation_server.c
    // 的 resolve_source_node()。
    UA_String_clear(&clientConfig->sessionName);
    clientConfig->sessionName = UA_STRING_ALLOC(sensor_session);

    time_t last_try = 0;
    printf("Entering background polling mode: attempting to connect to Aggregation Server...\n");

    while(running) {
        UA_Server_run_iterate(server, 0); // 改用 0 避免阻塞

        if (!syslog_connected) {
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                if(UA_Client_connect(syslogClient, "opc.tcp://127.0.0.1:4840") == UA_STATUSCODE_GOOD) {
                    syslog_connected = true;
                    printf("Connected successfully. Log forwarding started.\n");
                } else {
                    UA_Client_disconnect(syslogClient);
                }
            }
        } else {
            UA_Client_run_iterate(syslogClient, 0);

            UA_SecureChannelState channelState; UA_SessionState sessionState; UA_StatusCode connectStatus;
            UA_Client_getState(syslogClient, &channelState, &sessionState, &connectStatus);

            // 💡 終極防線：只要不是完美 OPEN，立刻切斷並靜音！避免洗版！
            if (channelState != UA_SECURECHANNELSTATE_OPEN) {
                syslog_connected = false;
                printf("Aggregation Server connection lost; switching to background reconnect mode...\n");
                UA_Client_disconnect(syslogClient);
                clear_log_queue(); // 斷線就清空佇列，重連後不要一次補送一堆舊訊息
            } else {
                // 💡 每個迴圈最多送一筆，分散開來，不會在同一個 tick 裡
                // 連續觸發好幾十次阻塞呼叫、卡住 server 正在處理的 handshake。
                flush_log_queue_once();
            }
        }

        // 💡 終極效能鎖：強制每次迴圈休眠 10 毫秒，保證 CPU 永遠維持在 0% ~ 1%！
        usleep(10000);
    }

    UA_Server_run_shutdown(server);
    if(syslogClient) { UA_Client_disconnect(syslogClient); UA_Client_delete(syslogClient); }
    UA_Server_delete(server);
    return 0;
}
