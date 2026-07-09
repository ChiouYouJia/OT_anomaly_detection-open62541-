#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_pubsub.h>
#include <open62541/server_config_default.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>

UA_Boolean running = true;
UA_NodeId distanceNodeId;
UA_NodeId connectionIdent, publishedDataSetIdent, writerGroupIdent;
UA_Client *syslogClient = NULL; 

// ================= [防護升級：全域儲存官方原生 Logger] =================
static void (*original_logger)(void *, UA_LogLevel, UA_LogCategory, const char *, va_list) = NULL;

static void stopHandler(int sig) { running = false; }

static void customLogger(void *logContext, UA_LogLevel level, UA_LogCategory category, const char *msg, va_list args) {
    // 💡 防護機制 1：只有我們自己的 USERLAND 日誌才做字串解析，避免底層 %N, %S 造成記憶體崩潰
    if (syslogClient && category == UA_LOGCATEGORY_USERLAND) {
        
        // 💡 防護機制 2：複製一份 va_list，因為 vsnprintf 會消耗掉 args 指標
        va_list args_copy;
        va_copy(args_copy, args);
        
        char msg_buf[256];
        vsnprintf(msg_buf, sizeof(msg_buf), msg, args_copy);
        va_end(args_copy); // 釋放複製的指標

        UA_DateTime now = UA_DateTime_now();
        UA_DateTimeStruct dts = UA_DateTime_toStruct(now);

        const char *levelNames[] = {"trace", "debug", "info", "warn", "error", "fatal"};
        // 確保 level 處於安全邊界，防止陣列越界
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

    // 💡 防護機制 3：將執行權交還給官方預設的 Logger，完美的終端機輸出就交給它！
    if (original_logger) {
        original_logger(logContext, level, category, msg, args);
    }
}
// =========================================================================

double read_distance(void){
    double min = 2.0, max = 50.0;
    return min + ((double)rand() / (RAND_MAX / (max - min)));
}

static void updateDistanceCallback(UA_Server *server, void *data) {
    UA_Double distance = read_distance();
    if (distance > 0) {
        UA_Variant value;
        UA_Variant_setScalar(&value, &distance, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, distanceNodeId, value);
        
        UA_LOG_INFO(UA_Server_getConfig(server)->logging, UA_LOGCATEGORY_USERLAND, 
                    "[Sensor] 📡 廣播距離: %.1f cm", distance);
    }
}

static void addPubSubConnection(UA_Server *server) {
    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("UADP Connection 1");
    connectionConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkAddressUrl = {UA_STRING(""), UA_STRING("opc.udp://224.0.2.14:4843/")};
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    connectionConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    connectionConfig.publisherId.id.uint16 = 2234;
    UA_Server_addPubSubConnection(server, &connectionConfig, &connectionIdent);
}

static void addPublishedDataSet(UA_Server *server) {
    UA_PublishedDataSetConfig publishedDataSetConfig;
    memset(&publishedDataSetConfig, 0, sizeof(UA_PublishedDataSetConfig));
    publishedDataSetConfig.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS;
    publishedDataSetConfig.name = UA_STRING("Demo PDS");
    UA_Server_addPublishedDataSet(server, &publishedDataSetConfig, &publishedDataSetIdent);
}

static void addDataSetField(UA_Server *server) {
    UA_DataSetFieldConfig dataSetFieldConfig;
    memset(&dataSetFieldConfig, 0, sizeof(UA_DataSetFieldConfig));
    dataSetFieldConfig.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    dataSetFieldConfig.field.variable.fieldNameAlias = UA_STRING("Sensor Distance");
    dataSetFieldConfig.field.variable.publishParameters.publishedVariable = distanceNodeId;
    dataSetFieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_Server_addDataSetField(server, publishedDataSetIdent, &dataSetFieldConfig, NULL);
}

static void addWriterGroup(UA_Server *server) {
    UA_WriterGroupConfig writerGroupConfig;
    memset(&writerGroupConfig, 0, sizeof(UA_WriterGroupConfig));
    writerGroupConfig.name = UA_STRING("Demo WriterGroup");
    writerGroupConfig.publishingInterval = 1000; 
    writerGroupConfig.writerGroupId = 100;
    writerGroupConfig.encodingMimeType = UA_PUBSUB_ENCODING_UADP;
    
    UA_UadpWriterGroupMessageDataType *writerGroupMessage = UA_UadpWriterGroupMessageDataType_new();
    writerGroupMessage->networkMessageContentMask = (UA_UadpNetworkMessageContentMask)(UA_UADPNETWORKMESSAGECONTENTMASK_PUBLISHERID | UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER | UA_UADPNETWORKMESSAGECONTENTMASK_WRITERGROUPID | UA_UADPNETWORKMESSAGECONTENTMASK_PAYLOADHEADER);
    writerGroupConfig.messageSettings.encoding = UA_EXTENSIONOBJECT_DECODED;
    writerGroupConfig.messageSettings.content.decoded.type = &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE];
    writerGroupConfig.messageSettings.content.decoded.data = writerGroupMessage;

    UA_Server_addWriterGroup(server, connectionIdent, &writerGroupConfig, &writerGroupIdent);
    UA_UadpWriterGroupMessageDataType_delete(writerGroupMessage);
}

static void addDataSetWriter(UA_Server *server) {
    UA_DataSetWriterConfig dataSetWriterConfig;
    memset(&dataSetWriterConfig, 0, sizeof(UA_DataSetWriterConfig));
    dataSetWriterConfig.name = UA_STRING("Demo DataSetWriter");
    dataSetWriterConfig.dataSetWriterId = 62541;
    dataSetWriterConfig.keyFrameCount = 10;
    UA_Server_addDataSetWriter(server, writerGroupIdent, publishedDataSetIdent, &dataSetWriterConfig, NULL);
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);
    srand(time(NULL));

    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    clientConfig->clientDescription.applicationUri = UA_STRING_ALLOC("urn:open62541.sensor.logclient");
    clientConfig->clientDescription.applicationName.text = UA_STRING_ALLOC("SensorLogClient");
    
    // 💡 備份並綁定 Proxy Logger
    if (!original_logger) original_logger = clientConfig->logging->log;
    clientConfig->logging->log = customLogger;

    if(UA_Client_connect(syslogClient, "opc.tcp://localhost:4840") != UA_STATUSCODE_GOOD) {
        printf("⚠️ Log Server 未啟動，本次執行將不會上報日誌。\n");
        UA_Client_delete(syslogClient);
        syslogClient = NULL;
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4842, NULL); 

    // 💡 備份並綁定 Proxy Logger (為了雙重保險再次確認)
    if (!original_logger) original_logger = config->logging->log;
    config->logging->log = customLogger;

    if(syslogClient) {
        UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "✅ 成功連接日誌控制中心");
    }

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Double initialDistance = 0.0;
    UA_Variant_setScalar(&attr.value, &initialDistance, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "DistanceValue");
    distanceNodeId = UA_NODEID_STRING(1, "DistanceValue");
    UA_Server_addVariableNode(server, distanceNodeId, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "Distance Sensor"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attr, NULL, NULL);

    UA_Server_addRepeatedCallback(server, (UA_ServerCallback)updateDistanceCallback, NULL, 1000, NULL);

    addPubSubConnection(server);
    addPublishedDataSet(server);
    addDataSetField(server);
    addWriterGroup(server);
    addDataSetWriter(server); 

    UA_Server_enableAllPubSubComponents(server);

    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "Sensor Server 上線 (無加密 UDP 廣播)...");
    UA_Server_run(server, &running);

    if(syslogClient) {
        UA_Client_disconnect(syslogClient);
        UA_Client_delete(syslogClient);
    }
    UA_Server_delete(server);
    return 0;
}