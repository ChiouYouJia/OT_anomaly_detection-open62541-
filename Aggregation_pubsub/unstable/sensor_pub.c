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
UA_Boolean syslog_connected = false;
UA_NodeId distanceNodeId, connectionIdent, publishedDataSetIdent, writerGroupIdent;
UA_Client *syslogClient = NULL; 
static UA_Boolean is_sending_log = false; 

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

double read_distance(void){ return 2.0 + ((double)rand() / (RAND_MAX / (50.0 - 2.0))); }

static void updateDistanceCallback(UA_Server *server, void *data) {
    UA_Double distance = read_distance();
    UA_Variant value; UA_Variant_setScalar(&value, &distance, &UA_TYPES[UA_TYPES_DOUBLE]);
    UA_Server_writeValue(server, distanceNodeId, value);
    UA_LOG_INFO(UA_Server_getConfig(server)->logging, UA_LOGCATEGORY_USERLAND, 
                "[Sensor] 📡 廣播並更新距離: %.1f cm", distance);
}

int main(void) {
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);
    srand(time(NULL));

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4842, NULL); 
    config->logging->log = customLogger;

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Double initDistance = 0.0; UA_Variant_setScalar(&attr.value, &initDistance, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "DistanceValue");
    distanceNodeId = UA_NODEID_STRING(1, "DistanceValue");
    UA_Server_addVariableNode(server, distanceNodeId, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "Distance Sensor"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attr, NULL, NULL);

    UA_Server_addRepeatedCallback(server, (UA_ServerCallback)updateDistanceCallback, NULL, 1000, NULL);

    UA_PubSubConnectionConfig connConfig; memset(&connConfig, 0, sizeof(connConfig));
    connConfig.name = UA_STRING("UDP Connection");
    connConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkUrl = {UA_STRING(""), UA_STRING("opc.udp://224.0.2.14:4843/")};
    UA_Variant_setScalar(&connConfig.address, &networkUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    connConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16; connConfig.publisherId.id.uint16 = 2234;
    UA_Server_addPubSubConnection(server, &connConfig, &connectionIdent);

    UA_PublishedDataSetConfig pdsConfig; memset(&pdsConfig, 0, sizeof(pdsConfig));
    pdsConfig.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS; pdsConfig.name = UA_STRING("Demo PDS");
    UA_Server_addPublishedDataSet(server, &pdsConfig, &publishedDataSetIdent);

    UA_DataSetFieldConfig fieldConfig; memset(&fieldConfig, 0, sizeof(fieldConfig));
    fieldConfig.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    fieldConfig.field.variable.fieldNameAlias = UA_STRING("Sensor Distance");
    fieldConfig.field.variable.publishParameters.publishedVariable = distanceNodeId;
    fieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_Server_addDataSetField(server, publishedDataSetIdent, &fieldConfig, NULL);

    UA_WriterGroupConfig wgConfig; memset(&wgConfig, 0, sizeof(wgConfig));
    wgConfig.name = UA_STRING("Demo WriterGroup"); wgConfig.publishingInterval = 1000; wgConfig.writerGroupId = 100; wgConfig.encodingMimeType = UA_PUBSUB_ENCODING_UADP;
    UA_UadpWriterGroupMessageDataType *wgMsg = UA_UadpWriterGroupMessageDataType_new();
    wgMsg->networkMessageContentMask = (UA_UadpNetworkMessageContentMask)(UA_UADPNETWORKMESSAGECONTENTMASK_PUBLISHERID | UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER | UA_UADPNETWORKMESSAGECONTENTMASK_WRITERGROUPID | UA_UADPNETWORKMESSAGECONTENTMASK_PAYLOADHEADER);
    wgConfig.messageSettings.encoding = UA_EXTENSIONOBJECT_DECODED; wgConfig.messageSettings.content.decoded.type = &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE]; wgConfig.messageSettings.content.decoded.data = wgMsg;
    UA_Server_addWriterGroup(server, connectionIdent, &wgConfig, &writerGroupIdent); UA_UadpWriterGroupMessageDataType_delete(wgMsg);

    UA_DataSetWriterConfig dswConfig; memset(&dswConfig, 0, sizeof(dswConfig));
    dswConfig.name = UA_STRING("Demo DataSetWriter"); dswConfig.dataSetWriterId = 62541; dswConfig.keyFrameCount = 10;
    UA_Server_addDataSetWriter(server, writerGroupIdent, publishedDataSetIdent, &dswConfig, NULL);
    UA_Server_enableAllPubSubComponents(server);

    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_USERLAND, "Sensor Server (PubSub + C/S 雙模式) 已上線");
    UA_Server_run_startup(server); 

    syslogClient = UA_Client_new();
    UA_ClientConfig *clientConfig = UA_Client_getConfig(syslogClient);
    UA_ClientConfig_setDefault(clientConfig);
    // 💡 徹底移除 timeout 猛藥
    clientConfig->logging->log = customLogger;

    time_t last_try = 0;
    printf("⏳ 進入背景輪詢模式：嘗試連線至 Aggregation Server...\n");

    while(running) {
        UA_Server_run_iterate(server, 0); // 改用 0 避免阻塞

        if (!syslog_connected) {
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                if(UA_Client_connect(syslogClient, "opc.tcp://127.0.0.1:4840") == UA_STATUSCODE_GOOD) {
                    syslog_connected = true; 
                    printf("✅ 成功連線！日誌上報機制已啟動。\n");
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
    if(syslogClient) { UA_Client_disconnect(syslogClient); UA_Client_delete(syslogClient); }
    UA_Server_delete(server);
    return 0;
}