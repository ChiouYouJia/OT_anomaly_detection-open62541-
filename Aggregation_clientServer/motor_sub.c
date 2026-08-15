#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <lgpio.h>

// 💡 Client/Server 版：motor 不再用 PubSub Reader 訂閱 multicast。它改當
// sensor_pub（@4842）的 OPC UA client，訂閱 DistanceValue 節點，收到資料
// 變更就驅動伺服馬達。這與 aggregation_server 連 sensor 的做法一致（見
// aggregation_server.c）。原本的 UDP multicast ReaderGroup/DataSetReader
// 與本地 server（@4801）已全部移除——motor 現在純粹是兩個 client：
//   - sensorClient：訂閱 sensor 的距離，驅動馬達
//   - syslogClient：把自己的 log 轉送到 aggregation_server 的 CentralLogIn

#define SERVO_PIN 18
#define PWM_FREQ 50.0
#define SAFE_DISTANCE 20.0

// ===== 多實例支援（1 sensor + N motor 拓撲）=====
// 同一支程式可啟動多個 motor 實例，各自有**不同的身分**。這對兩件事是必要的：
//   (1) SourceNode 歸屬：若三個 motor 都叫 "MotorSource"，伺服器蓋出來的
//       SourceNode 完全相同 → 無法分辨是哪一台，來源歸屬就失去意義。
//   (2) GNN 圖建構：節點必須可區分，否則三個 motor 會塌縮成同一個節點。
//
// 用法： ./motor_sub [id]      id = 1..N（預設 1，行為與單實例時完全相同）
//   id=1 → sessionName "MotorSource"   （**保持原名**，確保既有資料/腳本相容）
//   id>1 → sessionName "MotorSource<id>"
static int   motor_id = 1;
static char  motor_session[32] = "MotorSource";   // 送給 server 的 session 名
static int   sensor_id = 1;                       // 訂閱哪一台 sensor（見 main() 說明）
static char  sensor_url[64] = "opc.tcp://127.0.0.1:4842";
static char  motor_srcname[32] = "Motor";         // log 行內的 SourceName

// GPIO：多實例時每台用不同腳位，避免互搶同一支 PWM。
// 本機無 GPIO 時 gpio_handle < 0，以下全部略過（不影響 log 行為）。
static int servo_pin(void) { return SERVO_PIN + (motor_id - 1); }

UA_Boolean running = true;
int gpio_handle = -1;
UA_Client *syslogClient = NULL;
UA_Boolean syslog_connected = false;

// 💡 關鍵重構：customLogger 絕對不可以直接呼叫 UA_Client_* 這種會阻塞、
// 會重入 client 內部狀態機的函式。修法：logger 只負責把訊息「排隊」，真正
// 送出的動作全部移到主迴圈，而且主迴圈每次最多送一筆。
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

    // 💡 用 open62541 自家的 va_list 版格式化器 UA_String_vformat 展開，
    // 正確處理 %S/%N/%Q 等自訂符號，避免丟給 glibc vsnprintf 造成 SEGV。
    // 只做字串格式化、不碰 client/server 狀態，從 logger 呼叫安全。
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
    const char *sourceName = (category == UA_LOGCATEGORY_USERLAND) ? motor_srcname : "System";

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

    // 💡 重複行抑制
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

    // 💡 只排隊，絕不在這裡呼叫任何 UA_Client_* API。
    if (syslog_connected) {
        enqueue_log(full_log);
    }
}

// sensor 的 DistanceValue 每次變更就觸發（client 訂閱回呼）：依距離驅動馬達。
static void sensorDistanceChanged(UA_Client *client, UA_UInt32 subId, void *subContext,
                                  UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    if (!(value && value->hasValue && UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DOUBLE])))
        return;
    UA_Double currentDistance = *(UA_Double*)value->value.data;
    UA_Logger *logger = UA_Client_getConfig(client)->logging;

    // 收到值本身先記一筆（不論有無 GPIO），這是「我收到了」的憑據。
    UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "[Motor] Received distance: %.1f cm", currentDistance);

    // ---- 致動決策：日誌與 GPIO 解耦 ----
    // ⚠ 這裡原本把兩行 LOG 包在 `if (gpio_handle >= 0)` 裡面，造成一個嚴重的
    //   資料集缺陷：本機無 GPIO → benign log 永遠不會出現 "Distance too close /
    //   safe" 這兩個模板，而 R(否認) 攻擊偽造的正是這種行。結果任何模型只要看到
    //   該模板就 100% 命中 —— 那是模板新穎性的功勞，不是偵測能力。
    //   實證：R 攻擊 19 行全部異常、benign 0 行（見 ml/out/ngram_vs_deeplog.txt 的
    //   seen-only 拆解）。
    //
    //   真實部署裡，馬達控制器不論有沒有接上硬體都會記錄自己的決策。因此改成
    //   「一律記錄決策，只有實際 PWM 輸出才需要 GPIO」。這樣 benign 資料裡就會
    //   自然出現 too close / safe，R 攻擊必須靠伺服器蓋章的 SourceNode 才能分辨
    //   —— 那才是 OPC UA Part 22 這套設計真正要證明的事。
    if (currentDistance < SAFE_DISTANCE) {
        if (gpio_handle >= 0) lgTxPwm(gpio_handle, servo_pin(), PWM_FREQ, 5.0, 0, 0);
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_USERLAND, "[Motor] Distance too close (%.1f); rotating motor to 0 degrees", currentDistance);
    } else {
        if (gpio_handle >= 0) lgTxPwm(gpio_handle, servo_pin(), PWM_FREQ, 7.5, 0, 0);
        UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "[Motor] Distance safe (%.1f); rotating motor to 90 degrees", currentDistance);
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);

    // ---- 實例身分（1 sensor + N motor 拓撲）----
    // 不帶參數時 motor_id=1、sessionName="MotorSource"，與改造前完全一致，
    // 既有腳本與既有採集資料不受影響。
    if (argc > 1) {
        motor_id = atoi(argv[1]);
        if (motor_id < 1) {
            fprintf(stderr, "用法: %s [motor_id>=1] [sensor_id>=1]\n", argv[0]);
            return 1;
        }
    }
    // ---- 訂閱哪一台 sensor（項目 2 拓撲放大；預設 1 = 原本的單 sensor 行為）----
    // 多 sensor 時，「該一致的那群」＝訂閱同一台 sensor 的那群 motor。
    // 這個分群關係只存在於**訂閱邊**裡，是 GNN 拿得到、全域平特徵拿不到的資訊。
    if (argc > 2) {
        sensor_id = atoi(argv[2]);
        if (sensor_id < 1 || sensor_id > 64) {
            fprintf(stderr, "sensor_id 需為 1..64\n");
            return 1;
        }
    }
    snprintf(sensor_url, sizeof(sensor_url),
             "opc.tcp://127.0.0.1:%d", 4841 + sensor_id);
    if (motor_id == 1) {
        snprintf(motor_session, sizeof(motor_session), "MotorSource");
        snprintf(motor_srcname, sizeof(motor_srcname), "Motor");
    } else {
        snprintf(motor_session, sizeof(motor_session), "MotorSource%d", motor_id);
        snprintf(motor_srcname, sizeof(motor_srcname), "Motor%d", motor_id);
    }

    gpio_handle = lgGpiochipOpen(4);
    if (gpio_handle >= 0) {
        lgGpioClaimOutput(gpio_handle, 0, servo_pin(), 0);
        lgTxPwm(gpio_handle, servo_pin(), PWM_FREQ, 5.0, 0, 0);
    }

    // sensorClient：訂閱 sensor@4842 的 DistanceValue（取代原本的 PubSub Reader）。
    UA_Client *sensorClient = UA_Client_new();
    UA_ClientConfig *sensorConfig = UA_Client_getConfig(sensorClient);
    UA_ClientConfig_setDefault(sensorConfig);
    sensorConfig->logging->log = customLogger;
    // 💡 逾時 2000ms：與 aggregation_server 連 sensor 的設定一致，足夠完成握手三來回。
    sensorConfig->timeout = 2000;

    // syslogClient：把 log 轉送到 aggregation_server@4840 的 CentralLogIn。
    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    clientConfig->logging->log = customLogger;

    // OPC UA Part 22 LogRecord / SourceNode 來源歸屬：
    // 具名 session 讓 aggregation_server 能辨識來源，並由「伺服器端」蓋上
    // SourceNode=ns=1;s=MotorSource。repudiation_attack 以匿名連線注入的偽造
    // motor log 會被蓋上 SourceNode=null → 與真 motor 明確可分。
    // 詳見 aggregation_server.c 的 resolve_source_node()。
    // 多實例時每台 motor 用不同 session 名 → 伺服器蓋出不同的 SourceNode，
    // 三台 motor 在 log 上可明確區分（GNN 的節點身分即由此而來）。
    UA_String_clear(&clientConfig->sessionName);
    clientConfig->sessionName = UA_STRING_ALLOC(motor_session);

    UA_LOG_INFO(sensorConfig->logging, UA_LOGCATEGORY_USERLAND, "Motor client started; subscribing to sensor DistanceValue (Client/Server mode)...");

    // sensor 連線狀態機：0 未連 / 1 async 握手中 / 2 已訂閱
    // 用非阻塞 connectAsync + 每輪 run_iterate 推進握手，避免阻塞主迴圈（見專案原則 4）。
    int sensorPhase = 0;
    time_t sensor_last_try = 0;
    time_t syslog_last_try = 0;
    printf("Entering background polling mode: connecting to Sensor & Aggregation Server...\n");

    while (running) {
        // ---- sensor 距離訂閱 ----
        if (sensorPhase == 0) {
            if (time(NULL) - sensor_last_try >= 3) {
                sensor_last_try = time(NULL);
                UA_Client_connectAsync(sensorClient, sensor_url);
                sensorPhase = 1;
            }
        } else {
            // 💡 這裡的 timeout 一定要 > 0（用 10ms），讓 client 內部的 PublishRequest
            // 週期能被排程；motor 沒有自己的 server 迴圈，run_iterate(…,0) 會餓死 publish。
            UA_Client_run_iterate(sensorClient, 10);
            UA_SecureChannelState chState; UA_SessionState sessState; UA_StatusCode connStat;
            UA_Client_getState(sensorClient, &chState, &sessState, &connStat);

            // 💡 血淚教訓：不要在 session「剛」ACTIVATED 的同一輪就建 subscription！
            // 這是本專案反覆出現的競態根因：session 才剛 activated 時，client 內部的
            // publish 狀態機尚未完全就緒，此刻同步建立的 subscription/monitoredItem 會
            // 拿到一個「server 有、client 追蹤不到」的狀態，之後 server 送 notification
            // 過來就一直報 "Could not process a notification with clienthandle 1"，
            // 且 [Motor] Received distance 一筆都收不到。之前把 timeout 從 0 改 10ms
            // 只是讓競態「比較不容易踩到」，不是真的修好——長時間跑（如 3 小時 baseline）
            // 仍會踩中。真正的修法：activated 後先多跑 WARMUP_ITERS 輪 run_iterate 讓
            // publish 狀態機穩定，再建 subscription。
            //（aggregation_server 用同寫法卻穩，是因為它主迴圈有 UA_Server_run_iterate(…,10)
            //  撐住節奏、且只有單一 client，較不易踩到這個 timing 競態。）
            static int warmup = 0;
            if (sensorPhase == 1 && sessState == UA_SESSIONSTATE_ACTIVATED) {
                #define WARMUP_ITERS 20            // 約 20 輪 × 10ms ≈ 200ms 暖機
                if (warmup < WARMUP_ITERS) {
                    warmup++;                      // 先讓 publish 狀態機跑順，這輪先不建訂閱
                } else {
                    warmup = 0;
                    UA_LOG_INFO(sensorConfig->logging, UA_LOGCATEGORY_USERLAND, "Connected to sensor backend; subscribing to distance updates");
                    UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
                    UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(sensorClient, request, NULL, NULL, NULL);
                    if (response.responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
                        UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "DistanceValue"));
                        UA_MonitoredItemCreateResult mres = UA_Client_MonitoredItems_createDataChange(
                            sensorClient, response.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH,
                            monRequest, NULL, sensorDistanceChanged, NULL);
                        if (mres.statusCode == UA_STATUSCODE_GOOD)
                            sensorPhase = 2;         // 訂閱＋監控項都成功才進 phase 2
                        else
                            UA_Client_disconnect(sensorClient), sensorPhase = 0;  // 失敗→重來
                    } else {
                        UA_Client_disconnect(sensorClient); sensorPhase = 0;      // 訂閱失敗→重來
                    }
                }
            } else if (sensorPhase == 1) {
                warmup = 0;   // 還沒 activated（或中途掉了）→ 暖機計數歸零
            }

            if (sensorPhase == 2 && chState == UA_SECURECHANNELSTATE_CLOSED) {
                UA_LOG_WARNING(sensorConfig->logging, UA_LOGCATEGORY_USERLAND, "Sensor connection lost; switching to background reconnect mode");
                UA_Client_disconnect(sensorClient);
                sensorPhase = 0;
            } else if (sensorPhase == 1 && time(NULL) - sensor_last_try >= 3) {
                // 3 秒內握手仍未 activated → 放棄這次握手、收乾淨，下一輪重試
                UA_Client_disconnect(sensorClient);
                sensorPhase = 0;
            }
        }

        // ---- syslog 上報 ----
        if (!syslog_connected) {
            if (time(NULL) - syslog_last_try >= 3) {
                syslog_last_try = time(NULL);
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
                flush_log_queue_once();
            }
        }

        // 💡 終極效能鎖：強制每次迴圈休眠 10 毫秒，保證 CPU 永遠維持在 0% ~ 1%！
        usleep(10000);
    }

    if (gpio_handle >= 0) { lgTxPwm(gpio_handle, servo_pin(), PWM_FREQ, 0.0, 0, 0); lgGpioFree(gpio_handle, servo_pin()); lgGpiochipClose(gpio_handle); }
    UA_Client_disconnect(sensorClient); UA_Client_delete(sensorClient);
    if(syslogClient) { UA_Client_disconnect(syslogClient); UA_Client_delete(syslogClient); }
    return 0;
}
