#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
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
static UA_Boolean is_sending_log = false;

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

    char msg_buf[512];
    if (category == UA_LOGCATEGORY_USERLAND) {
        va_list args_copy; va_copy(args_copy, args);
        vsnprintf(msg_buf, sizeof(msg_buf), msg, args_copy); va_end(args_copy);
    } else {
        snprintf(msg_buf, sizeof(msg_buf), "[System] %s", msg);
    }

    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
    char full_log[1024];
    snprintf(full_log, sizeof(full_log), "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/%s\t%s", 
             dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec, dts.milliSec, levelStr, catStr, msg_buf);

    printf("%s\n", full_log);

    if (syslogClient && syslog_connected && !is_sending_log) {
        is_sending_log = true; 
        UA_Variant val; UA_String ua_msg = UA_STRING(full_log);
        UA_Variant_setScalar(&val, &ua_msg, &UA_TYPES[UA_TYPES_STRING]);
        UA_Client_writeValueAttribute(syslogClient, UA_NODEID_STRING(1, "CentralLog"), &val);
        is_sending_log = false; 
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
                UA_LOG_WARNING(logger, UA_LOGCATEGORY_USERLAND, "[Motor] ⚠️ 距離過近(%.1f)！馬達轉至 0 度", currentDistance);
            } else {
                lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 7.5, 0, 0);
                UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "[Motor] ✅ 距離安全(%.1f)，馬達轉至 90 度", currentDistance);
            }
        } else {
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "[Motor] 收到 PubSub 距離: %.1f cm", currentDistance);
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

    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "Motor Sub 啟動，PubSub 監聽中...");
    UA_Server_run_startup(server); 

    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    // 💡 徹底移除 timeout 猛藥
    clientConfig->logging->log = customLogger;

    time_t last_try = 0;
    printf("⏳ 進入背景輪詢模式：嘗試連線至 Aggregation Server...\n");

    while (running) {
        UA_Server_run_iterate(server, 0);
        
        if (!syslog_connected) {
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                if(UA_Client_connect(syslogClient, "opc.tcp://127.0.0.1:4840") == UA_STATUSCODE_GOOD) {
                    syslog_connected = true; 
                    printf("✅ 成功連線！Motor 日誌上報機制已啟動。\n");
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
                printf("⚠️ Aggregation Server 連線中斷，切換為背景重連模式...\n");
                UA_Client_disconnect(syslogClient);
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