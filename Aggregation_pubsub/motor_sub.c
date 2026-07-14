#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
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

static void (*original_logger)(void *, UA_LogLevel, UA_LogCategory, const char *, va_list) = NULL;
static void stopHandler(int sig) { running = false; }

static void customLogger(void *logContext, UA_LogLevel level, UA_LogCategory category, const char *msg, va_list args) {
    if (syslogClient && category == UA_LOGCATEGORY_USERLAND) {
        va_list args_copy; va_copy(args_copy, args);
        char msg_buf[256]; vsnprintf(msg_buf, sizeof(msg_buf), msg, args_copy);
        va_end(args_copy);

        UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
        const char *levelStr = "unknown";
        switch (level) {
            case UA_LOGLEVEL_TRACE:   levelStr = "trace"; break;
            case UA_LOGLEVEL_DEBUG:   levelStr = "debug"; break;
            case UA_LOGLEVEL_INFO:    levelStr = "info"; break;
            case UA_LOGLEVEL_WARNING: levelStr = "warn"; break;
            case UA_LOGLEVEL_ERROR:   levelStr = "error"; break;
            case UA_LOGLEVEL_FATAL:   levelStr = "fatal"; break;
            default:                  levelStr = "unknown"; break;
        }
        char full_log[512];
        snprintf(full_log, sizeof(full_log), "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/application   %s", 
                 dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec, dts.milliSec, levelStr, msg_buf);

        UA_Variant val;
        UA_String ua_msg = UA_STRING(full_log);
        UA_Variant_setScalar(&val, &ua_msg, &UA_TYPES[UA_TYPES_STRING]);
        UA_Client_writeValueAttribute(syslogClient, UA_NODEID_STRING(1, "CentralLog"), &val);
    }
    if (original_logger) { original_logger(logContext, level, category, msg, args); }
}

// 💡 確保參數與 onWrite 簽名完全吻合
static void onDistanceDataChange(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, 
                                 const UA_NodeId *nodeId, void *nodeContext, const UA_NumericRange *range, 
                                 const UA_DataValue *value) {
    // 加上 value 存在的防呆機制
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
            // 在沒有 GPIO 硬體的環境下印出確認訊息
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

    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    if (!original_logger) original_logger = clientConfig->logging->log;
    clientConfig->logging->log = customLogger;

    if(UA_Client_connect(syslogClient, "opc.tcp://localhost:4840") != UA_STATUSCODE_GOOD) {
        UA_Client_delete(syslogClient); syslogClient = NULL;
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4801, NULL);
    if (!original_logger) original_logger = config->logging->log;
    config->logging->log = customLogger;

    UA_PubSubConnectionConfig connConfig;
    memset(&connConfig, 0, sizeof(connConfig));
    connConfig.name = UA_STRING("UDP Connection");
    connConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkUrl = {UA_STRING(""), UA_STRING("opc.udp://224.0.2.14:4843/")};
    UA_Variant_setScalar(&connConfig.address, &networkUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    UA_Server_addPubSubConnection(server, &connConfig, &connectionIdent);

    UA_ReaderGroupConfig rgConfig;
    memset(&rgConfig, 0, sizeof(rgConfig));
    rgConfig.name = UA_STRING("ReaderGroup1");
    UA_Server_addReaderGroup(server, connectionIdent, &rgConfig, &readerGroupIdent);

    UA_DataSetReaderConfig rConfig;
    memset(&rConfig, 0, sizeof(rConfig));
    rConfig.name = UA_STRING("DataSet Reader 1"); 
    rConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    rConfig.publisherId.id.uint16 = 2234; 
    rConfig.writerGroupId = 100; 
    rConfig.dataSetWriterId = 62541;
    
    UA_DataSetMetaDataType_init(&rConfig.dataSetMetaData);
    rConfig.dataSetMetaData.name = UA_STRING("Demo PDS"); 
    rConfig.dataSetMetaData.fieldsSize = 1;
    rConfig.dataSetMetaData.fields = (UA_FieldMetaData *)UA_Array_new(1, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
    UA_FieldMetaData_init(&rConfig.dataSetMetaData.fields[0]);
    
    // 💡 修正 1：給定絕對精確的 MetaData (一維、Double)
    rConfig.dataSetMetaData.fields[0].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    rConfig.dataSetMetaData.fields[0].builtInType = UA_NS0ID_DOUBLE; 
    rConfig.dataSetMetaData.fields[0].valueRank = UA_VALUERANK_SCALAR;
    
    UA_Server_addDataSetReader(server, readerGroupIdent, &rConfig, &readerIdent);

    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "LocalDistance");
    vAttr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    vAttr.valueRank = UA_VALUERANK_SCALAR; 
    UA_Double initVal = 0.0; 
    UA_Variant_setScalar(&vAttr.value, &initVal, &UA_TYPES[UA_TYPES_DOUBLE]); 
    
    UA_NodeId targetNode = UA_NODEID_NULL; 
    UA_Server_addVariableNode(server, targetNode, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "LocalDistance"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), vAttr, NULL, &targetNode); 

    UA_FieldTargetDataType targetVar;
    memset(&targetVar, 0, sizeof(targetVar));
    targetVar.attributeId = UA_ATTRIBUTEID_VALUE; 
    targetVar.targetNodeId = targetNode; 
    UA_Server_DataSetReader_createTargetVariables(server, readerIdent, 1, &targetVar);

    // 💡 修正 2：明確指定將函式綁定到「被寫入 (onWrite)」事件
    UA_ValueCallback callback;
    memset(&callback, 0, sizeof(callback));
    callback.onWrite = onDistanceDataChange; 
    UA_Server_setVariableNode_valueCallback(server, targetNode, callback);
    
    UA_free(rConfig.dataSetMetaData.fields);
    UA_Server_enableAllPubSubComponents(server);
    
    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "Motor Sub 啟動，PubSub 監聽中...");
    
    // 💡 修正 3：使用非阻塞式的雙軌迭代，讓 Server 與 Syslog Client 都能健康運作
    UA_Server_run_startup(server);
    while (running) {
        UA_Server_run_iterate(server, 10);
        if (syslogClient) {
            UA_Client_run_iterate(syslogClient, 10);
        }
    }
    UA_Server_run_shutdown(server);

    if (gpio_handle >= 0) { lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 0.0, 0, 0); lgGpioFree(gpio_handle, SERVO_PIN); lgGpiochipClose(gpio_handle); }
    if(syslogClient) { UA_Client_disconnect(syslogClient); UA_Client_delete(syslogClient); }
    UA_Server_delete(server);
    return 0;
}