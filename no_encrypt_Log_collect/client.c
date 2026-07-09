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
UA_NodeId connectionIdentifier, readerGroupIdentifier, readerIdentifier;
UA_Client *syslogClient = NULL; 

// ================= [防護升級：全域儲存官方原生 Logger] =================
static void (*original_logger)(void *, UA_LogLevel, UA_LogCategory, const char *, va_list) = NULL;

static void stopHandler(int sig) { running = false; }

static void customLogger(void *logContext, UA_LogLevel level, UA_LogCategory category, const char *msg, va_list args) {
    if (syslogClient && category == UA_LOGCATEGORY_USERLAND) {
        va_list args_copy;
        va_copy(args_copy, args);
        
        char msg_buf[256];
        vsnprintf(msg_buf, sizeof(msg_buf), msg, args_copy);
        va_end(args_copy);

        UA_DateTime now = UA_DateTime_now();
        UA_DateTimeStruct dts = UA_DateTime_toStruct(now);

        const char *levelNames[] = {"trace", "debug", "info", "warn", "error", "fatal"};
        const char *levelStr = (level >= 0 && level <= 5) ? levelNames[level] : "unknown";

        char full_log[512];
        snprintf(full_log, sizeof(full_log), "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/application   %s", 
                 dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec, dts.milliSec, 
                 levelStr, msg_buf);

        UA_Variant val;
        UA_String ua_msg = UA_STRING(full_log);
        UA_Variant_setScalar(&val, &ua_msg, &UA_TYPES[UA_TYPES_STRING]);
        UA_Client_writeValueAttribute(syslogClient, UA_NODEID_STRING(1, "CentralLog"), &val);
    }

    if (original_logger) {
        original_logger(logContext, level, category, msg, args);
    }
}
// =========================================================================

static void onDistanceDataChange(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, const UA_NodeId *nodeId, void *nodeContext, const UA_NumericRange *range, const UA_DataValue *value) {
    if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DOUBLE])) {
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
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "[Motor] 收到距離: %.1f (無 GPIO 模式)", currentDistance);
        }
    }
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    gpio_handle = lgGpiochipOpen(4);
    if (gpio_handle >= 0) {
        lgGpioClaimOutput(gpio_handle, 0, SERVO_PIN, 0);
        lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 5.0, 0, 0);
    }

    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    clientConfig->clientDescription.applicationUri = UA_STRING_ALLOC("urn:open62541.motor.logclient");
    clientConfig->clientDescription.applicationName.text = UA_STRING_ALLOC("MotorLogClient");
    
    // 💡 備份並綁定 Proxy Logger
    if (!original_logger) original_logger = clientConfig->logging->log;
    clientConfig->logging->log = customLogger;

    if(UA_Client_connect(syslogClient, "opc.tcp://localhost:4840") != UA_STATUSCODE_GOOD) {
        printf("⚠️ Log Server 未啟動，不進行日誌上報。\n");
        UA_Client_delete(syslogClient);
        syslogClient = NULL;
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4801, NULL);

    // 💡 備份並綁定 Proxy Logger
    if (!original_logger) original_logger = config->logging->log;
    config->logging->log = customLogger;

    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("UDP Connection");
    connectionConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkAddressUrl = {UA_STRING(""), UA_STRING("opc.udp://224.0.2.14:4843/")};
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    UA_Server_addPubSubConnection(server, &connectionConfig, &connectionIdentifier);

    UA_ReaderGroupConfig readerGroupConfig;
    memset(&readerGroupConfig, 0, sizeof(UA_ReaderGroupConfig));
    readerGroupConfig.name = UA_STRING("ReaderGroup1");
    UA_Server_addReaderGroup(server, connectionIdentifier, &readerGroupConfig, &readerGroupIdentifier);

    UA_DataSetReaderConfig readerConfig;
    memset(&readerConfig, 0, sizeof(UA_DataSetReaderConfig));
    readerConfig.name = UA_STRING("DataSet Reader 1");
    readerConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    readerConfig.publisherId.id.uint16 = 2234;
    readerConfig.writerGroupId = 100;
    readerConfig.dataSetWriterId = 62541;

    UA_DataSetMetaDataType_init(&readerConfig.dataSetMetaData);
    readerConfig.dataSetMetaData.name = UA_STRING("Demo PDS");
    readerConfig.dataSetMetaData.fieldsSize = 1;
    readerConfig.dataSetMetaData.fields = (UA_FieldMetaData *)UA_Array_new(1, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
    UA_FieldMetaData_init(&readerConfig.dataSetMetaData.fields[0]);
    readerConfig.dataSetMetaData.fields[0].dataType = UA_NODEID_NULL;
    readerConfig.dataSetMetaData.fields[0].builtInType = 0; 
    readerConfig.dataSetMetaData.fields[0].valueRank = UA_VALUERANK_ANY;
    UA_Server_addDataSetReader(server, readerGroupIdentifier, &readerConfig, &readerIdentifier);

    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "LocalDistance");
    vAttr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    vAttr.valueRank = -1; 
    UA_Double initVal = 0.0;
    UA_Variant_setScalar(&vAttr.value, &initVal, &UA_TYPES[UA_TYPES_DOUBLE]); 

    UA_NodeId targetNode = UA_NODEID_NULL; 
    UA_Server_addVariableNode(server, targetNode, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "LocalDistance"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), vAttr, NULL, &targetNode); 

    UA_FieldTargetDataType targetVar;
    memset(&targetVar, 0, sizeof(targetVar));
    targetVar.attributeId = UA_ATTRIBUTEID_VALUE;
    targetVar.targetNodeId = targetNode; 
    UA_Server_DataSetReader_createTargetVariables(server, readerIdentifier, 1, &targetVar);

    UA_ValueCallback callback = {NULL, onDistanceDataChange};
    UA_Server_setVariableNode_valueCallback(server, targetNode, callback);
    UA_free(readerConfig.dataSetMetaData.fields);

    UA_Server_enableAllPubSubComponents(server);
    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "Motor Sub 啟動，準備接收無加密 UDP 資料...");
    UA_Server_run(server, &running);

    if (gpio_handle >= 0) {
        lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 0.0, 0, 0);
        lgGpioFree(gpio_handle, SERVO_PIN);
        lgGpiochipClose(gpio_handle);
    }
    if(syslogClient) {
        UA_Client_disconnect(syslogClient);
        UA_Client_delete(syslogClient);
    }
    UA_Server_delete(server);
    return 0;
}