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

static void (*original_logger)(void *, UA_LogLevel, UA_LogCategory, const char *, va_list) = NULL;
static void stopHandler(int sig) { running = false; }

// 自訂 Logger：將 Log 送往 Aggregation Server
static void customLogger(void *logContext, UA_LogLevel level, UA_LogCategory category, const char *msg, va_list args) {
    if (syslogClient && category == UA_LOGCATEGORY_USERLAND) {
        va_list args_copy;
        va_copy(args_copy, args);
        char msg_buf[256];
        vsnprintf(msg_buf, sizeof(msg_buf), msg, args_copy);
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

double read_distance(void){ return 2.0 + ((double)rand() / (RAND_MAX / (50.0 - 2.0))); }

static void updateDistanceCallback(UA_Server *server, void *data) {
    UA_Double distance = read_distance();
    UA_Variant value;
    UA_Variant_setScalar(&value, &distance, &UA_TYPES[UA_TYPES_DOUBLE]);
    UA_Server_writeValue(server, distanceNodeId, value);
    
    UA_LOG_INFO(UA_Server_getConfig(server)->logging, UA_LOGCATEGORY_USERLAND, 
                "[Sensor] 📡 廣播並更新距離: %.1f cm", distance);
}

int main(void) {
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);
    srand(time(NULL));

    // =========================================================================
    // 1. 初始化並啟動 Sensor 本身的 Server 與 PubSub
    // =========================================================================
    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4842, NULL); 
    if (!original_logger) original_logger = config->logging->log;
    config->logging->log = customLogger;

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Double initDistance = 0.0;
    UA_Variant_setScalar(&attr.value, &initDistance, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "DistanceValue");
    distanceNodeId = UA_NODEID_STRING(1, "DistanceValue");
    UA_Server_addVariableNode(server, distanceNodeId, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "Distance Sensor"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attr, NULL, NULL);

    UA_Server_addRepeatedCallback(server, (UA_ServerCallback)updateDistanceCallback, NULL, 1000, NULL);

    // 建立 PubSub (保留 OT 層即時通訊)
    UA_PubSubConnectionConfig connConfig;
    memset(&connConfig, 0, sizeof(connConfig));
    connConfig.name = UA_STRING("UDP Connection");
    connConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkUrl = {UA_STRING(""), UA_STRING("opc.udp://224.0.2.14:4843/")};
    UA_Variant_setScalar(&connConfig.address, &networkUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    connConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16; connConfig.publisherId.id.uint16 = 2234;
    UA_Server_addPubSubConnection(server, &connConfig, &connectionIdent);

    UA_PublishedDataSetConfig pdsConfig;
    memset(&pdsConfig, 0, sizeof(pdsConfig));
    pdsConfig.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS; pdsConfig.name = UA_STRING("Demo PDS");
    UA_Server_addPublishedDataSet(server, &pdsConfig, &publishedDataSetIdent);

    UA_DataSetFieldConfig fieldConfig;
    memset(&fieldConfig, 0, sizeof(fieldConfig));
    fieldConfig.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    fieldConfig.field.variable.fieldNameAlias = UA_STRING("Sensor Distance");
    fieldConfig.field.variable.publishParameters.publishedVariable = distanceNodeId;
    fieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_Server_addDataSetField(server, publishedDataSetIdent, &fieldConfig, NULL);

    UA_WriterGroupConfig wgConfig;
    memset(&wgConfig, 0, sizeof(wgConfig));
    wgConfig.name = UA_STRING("Demo WriterGroup");
    wgConfig.publishingInterval = 1000; wgConfig.writerGroupId = 100; wgConfig.encodingMimeType = UA_PUBSUB_ENCODING_UADP;
    
    UA_UadpWriterGroupMessageDataType *wgMsg = UA_UadpWriterGroupMessageDataType_new();
    wgMsg->networkMessageContentMask = (UA_UadpNetworkMessageContentMask)(UA_UADPNETWORKMESSAGECONTENTMASK_PUBLISHERID | UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER | UA_UADPNETWORKMESSAGECONTENTMASK_WRITERGROUPID | UA_UADPNETWORKMESSAGECONTENTMASK_PAYLOADHEADER);
    wgConfig.messageSettings.encoding = UA_EXTENSIONOBJECT_DECODED;
    wgConfig.messageSettings.content.decoded.type = &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE];
    wgConfig.messageSettings.content.decoded.data = wgMsg;

    UA_Server_addWriterGroup(server, connectionIdent, &wgConfig, &writerGroupIdent);
    UA_UadpWriterGroupMessageDataType_delete(wgMsg);

    UA_DataSetWriterConfig dswConfig;
    memset(&dswConfig, 0, sizeof(dswConfig));
    dswConfig.name = UA_STRING("Demo DataSetWriter"); dswConfig.dataSetWriterId = 62541; dswConfig.keyFrameCount = 10;
    UA_Server_addDataSetWriter(server, writerGroupIdent, publishedDataSetIdent, &dswConfig, NULL);

    UA_Server_enableAllPubSubComponents(server);
    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "Sensor Server (PubSub + C/S 雙模式) 已上線");

    // 💡 讓 Port 4842 立刻開始監聽！
    UA_Server_run_startup(server); 

    // =========================================================================
    // 2. 建立 Syslog Client 並在背景重試，同時保持 Server 運作
    // =========================================================================
    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    if (!original_logger) original_logger = clientConfig->logging->log;
    clientConfig->logging->log = customLogger;

    printf("⏳ 嘗試連線至 Aggregation Server (Port: 4840) 以啟用日誌上報...\n");
    
    while(running && UA_Client_connect(syslogClient, "opc.tcp://localhost:4840") != UA_STATUSCODE_GOOD) {
        printf("⚠️ 尚未找到 Aggregation Server，3 秒後自動重試...\n");
        for(int i = 0; i < 300 && running; i++) {
            UA_Server_run_iterate(server, 10);
            usleep(10000); 
        }
    }
    
    if (running) {
        printf("✅ 成功連線！Sensor 日誌上報機制已啟動。\n");
    } else {
        UA_Client_delete(syslogClient); 
        syslogClient = NULL;
    }

    // =========================================================================
    // 3. 正確的雙軌迴圈 (💡 這裡補上了漏掉的 Client Iterate)
    // =========================================================================
    while(running) {
        // 處理作為 Server (4842) 的網路請求與 PubSub 推播
        UA_Server_run_iterate(server, 10);
        
        // 處理作為 Client 向上拋 Log 的網路緩衝區，避免阻塞卡死！
        if (syslogClient) {
            UA_Client_run_iterate(syslogClient, 10);
        }
    }

    UA_Server_run_shutdown(server);
    if(syslogClient) { UA_Client_disconnect(syslogClient); UA_Client_delete(syslogClient); }
    UA_Server_delete(server);
    return 0;
}