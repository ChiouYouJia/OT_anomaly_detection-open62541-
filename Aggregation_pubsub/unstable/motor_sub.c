#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server_config_default.h>
#include <open62541/server.h>
#include <open62541/server_pubsub.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <lgpio.h>

#define SERVO_PIN 18
#define PWM_FREQ 50.0
#define SAFE_DISTANCE 20.0

UA_Boolean running = true;
int gpio_handle = -1;
UA_NodeId connectionIdent, readerGroupIdent, readerIdent;
UA_Client *syslogClient = NULL; 
UA_Boolean syslog_connected = false;

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
static char log_queue[LOG_QUEUE_SIZE][1024];
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

    // 💡 官方巨集絕對匹配
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

    // 💡 修正：不管是不是 USERLAND，都要先把 msg(格式字串) + args 用 vsnprintf 展開，
    // 不然 network/channel 這類 log（例如 "TCP %u | ..."）就會把 %u %s 原封不動印出來。
    //
    // 💡 但 UA_LOGCATEGORY_PUBSUB 例外！ASan 抓到：open62541 1.5.x 在組
    // ReaderGroup/DataSetWriter 狀態轉換的 log 訊息時，內部用 %s 直接印一個
    // 由 UA_String_fromChars 配置、但「沒有 null terminator」的 UA_String.data
    // （很可能就是你設定的 rgConfig.name / dswConfig.name 這類元件名稱）。
    // 一旦我們呼叫 vsnprintf 把它展開，printf 就會沿著這段沒有結尾符號的
    // buffer 一直找 \0，讀到緩衝區外面去，造成 heap-buffer-overflow——這是
    // library 內部的 bug，不是我們這邊能修的。所以 PUBSUB 類別乾脆不展開
    // 參數，退回顯示原始格式字串，用犧牲一點可讀性換穩定，其他類別維持
    // 正常展開。
    // 💡 open62541 的 log 訊息用的是「UA_String_format 的格式規則」，比 C 標準多了
    // %S(UA_String)、%N(UA_NodeId)、%Q(QualifiedName) 等自訂符號（見 plugin/log.h 註解）。
    // 直接丟給 glibc 的 vsnprintf，%S 會被當成 C 標準的「寬字元字串 wchar_t*」，於是 glibc
    // 拿下一個 vararg（其實是 UA_String）當寬字串指標去 wcsnlen/wcsrtombs → 讀亂數位址
    // → SEGV（ASan: __wcsnlen_avx2）。這與類別無關（PUBSUB、SECURECHANNEL 都會中）。
    // 正解：用 open62541 自家的 va_list 版格式化器 UA_String_vformat 展開——它就是內建
    // UA_Log_Stdout 用的同一支，能正確把 %S/%N/%Q 印成「可讀的真實值」（而不是崩潰、也不是
    // 殘留模板）。它只做字串格式化、不碰任何 client/server 內部狀態，從 logger 呼叫是安全的
    //（不違反「logger 不可呼叫 UA_Client_*/UA_Server_*」的鐵律）。
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

    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
    char full_log[1024];
    snprintf(full_log, sizeof(full_log), "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/%s\t%s", 
             dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec, dts.milliSec, levelStr, catStr, msg_buf);

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

static void onDistanceDataChange(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, 
                                 const UA_NodeId *nodeId, void *nodeContext, const UA_NumericRange *range, 
                                 const UA_DataValue *value) {
    if (value && value->hasValue && UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DOUBLE])) {
        UA_Double currentDistance = *(UA_Double*)value->value.data;
        UA_Logger *logger = UA_Server_getConfig(server)->logging;

        if (gpio_handle >= 0) {
            if (currentDistance < SAFE_DISTANCE) {
                lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 5.0, 0, 0);
                UA_LOG_WARNING(logger, UA_LOGCATEGORY_USERLAND, "[Motor] Distance too close (%.1f); rotating motor to 0 degrees", currentDistance);
            } else {
                lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 7.5, 0, 0);
                UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "[Motor] Distance safe (%.1f); rotating motor to 90 degrees", currentDistance);
            }
        } else {
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "[Motor] Received PubSub distance: %.1f cm", currentDistance);
        }
    }
}

int main(void) {
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);

    gpio_handle = lgGpiochipOpen(4);
    if (gpio_handle >= 0) {
        lgGpioClaimOutput(gpio_handle, 0, SERVO_PIN, 0);
        lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 5.0, 0, 0);
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4801, NULL);
    config->logging->log = customLogger;

    UA_PubSubConnectionConfig connConfig; memset(&connConfig, 0, sizeof(connConfig));
    connConfig.name = UA_STRING("UDP Connection");
    connConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkUrl = {UA_STRING(""), UA_STRING("opc.udp://224.0.2.14:4843/")};
    UA_Variant_setScalar(&connConfig.address, &networkUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    UA_Server_addPubSubConnection(server, &connConfig, &connectionIdent);

    UA_ReaderGroupConfig rgConfig; memset(&rgConfig, 0, sizeof(rgConfig));
    rgConfig.name = UA_STRING("ReaderGroup1");
    UA_Server_addReaderGroup(server, connectionIdent, &rgConfig, &readerGroupIdent);

    UA_DataSetReaderConfig rConfig; memset(&rConfig, 0, sizeof(rConfig));
    rConfig.name = UA_STRING("DataSet Reader 1"); 
    rConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16; rConfig.publisherId.id.uint16 = 2234; 
    rConfig.writerGroupId = 100; rConfig.dataSetWriterId = 62541;
    
    UA_DataSetMetaDataType_init(&rConfig.dataSetMetaData);
    rConfig.dataSetMetaData.name = UA_STRING("Demo PDS"); rConfig.dataSetMetaData.fieldsSize = 1;
    rConfig.dataSetMetaData.fields = (UA_FieldMetaData *)UA_Array_new(1, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
    UA_FieldMetaData_init(&rConfig.dataSetMetaData.fields[0]);
    rConfig.dataSetMetaData.fields[0].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    rConfig.dataSetMetaData.fields[0].builtInType = UA_NS0ID_DOUBLE; 
    rConfig.dataSetMetaData.fields[0].valueRank = UA_VALUERANK_SCALAR;
    UA_Server_addDataSetReader(server, readerGroupIdent, &rConfig, &readerIdent);

    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "LocalDistance");
    vAttr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId; vAttr.valueRank = UA_VALUERANK_SCALAR; 
    UA_Double initVal = 0.0; UA_Variant_setScalar(&vAttr.value, &initVal, &UA_TYPES[UA_TYPES_DOUBLE]); 
    
    UA_NodeId targetNode = UA_NODEID_NULL; 
    UA_Server_addVariableNode(server, targetNode, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "LocalDistance"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), vAttr, NULL, &targetNode); 

    UA_FieldTargetDataType targetVar; memset(&targetVar, 0, sizeof(targetVar));
    targetVar.attributeId = UA_ATTRIBUTEID_VALUE; targetVar.targetNodeId = targetNode; 
    UA_Server_DataSetReader_createTargetVariables(server, readerIdent, 1, &targetVar);

    UA_ValueCallback callback; memset(&callback, 0, sizeof(callback));
    callback.onWrite = onDistanceDataChange; 
    UA_Server_setVariableNode_valueCallback(server, targetNode, callback);
    
    UA_free(rConfig.dataSetMetaData.fields);
    UA_Server_enableAllPubSubComponents(server);

    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "Motor Sub started; listening on PubSub...");
    UA_Server_run_startup(server); 

    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    // 💡 徹底移除 timeout 猛藥
    clientConfig->logging->log = customLogger;

    time_t last_try = 0;
    printf("Entering background polling mode: attempting to connect to Aggregation Server...\n");

    while (running) {
        UA_Server_run_iterate(server, 0);
        
        if (!syslog_connected) {
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                if(UA_Client_connect(syslogClient, "opc.tcp://127.0.0.1:4840") == UA_STATUSCODE_GOOD) {
                    syslog_connected = true; 
                    printf("Connected successfully. Motor log forwarding started.\n");
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
    if (gpio_handle >= 0) { lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 0.0, 0, 0); lgGpioFree(gpio_handle, SERVO_PIN); lgGpiochipClose(gpio_handle); }
    if(syslogClient) { UA_Client_disconnect(syslogClient); UA_Client_delete(syslogClient); }
    UA_Server_delete(server);
    return 0;
}