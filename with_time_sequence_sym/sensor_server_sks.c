#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/server.h>
#include <open62541/server_pubsub.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/pki_default.h>
#define DEMO_SECURITYGROUPNAME "DemoSecurityGroup"
#define SKS_SERVER_DISCOVERYURL "opc.tcp://127.0.0.1:4841"

UA_Boolean running = true;
UA_NodeId distanceNodeId;
UA_NodeId connectionIdent, publishedDataSetIdent, writerGroupIdent;

static void stopHandler(int sig) { running = false; }

static UA_ByteString loadFile(const char *const path) {
    UA_ByteString fileContents = UA_STRING_NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return fileContents;
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t)ftell(fp);
    fileContents.data = (UA_Byte *)UA_malloc(fileContents.length);
    if (fileContents.data) {
        fseek(fp, 0, SEEK_SET);
        fread(fileContents.data, 1, fileContents.length, fp);
    }
    fclose(fp);
    return fileContents;
}

double read_distance(void){
    double min = 2.0;
    double max = 50.0;
    return min + ((double)rand() / (RAND_MAX / (max - min)));
}

static void updateDistanceCallback(UA_Server *server, void *data) {
    UA_Double distance = read_distance();
    if (distance > 0) {
        UA_Variant value;
        UA_Variant_setScalar(&value, &distance, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, distanceNodeId, value);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "📡 [加密廣播中] 目前距離: %.1f cm", distance);
    }
}

static void addPubSubConnection(UA_Server *server) {
    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("UADP Connection 1");
    connectionConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkAddressUrl = {UA_STRING_NULL, UA_STRING("opc.udp://127.0.0.1:4843/")};
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
    dataSetFieldConfig.field.variable.promotedField = UA_FALSE;
    dataSetFieldConfig.field.variable.publishParameters.publishedVariable = distanceNodeId;
    dataSetFieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_Server_addDataSetField(server, publishedDataSetIdent, &dataSetFieldConfig, NULL);
}

static void sksPullRequestCallback(UA_Server *server, UA_StatusCode sksPullRequestStatus, void *data) {
    UA_PubSubState state = UA_PUBSUBSTATE_OPERATIONAL;
    UA_Server_WriterGroup_getState(server, writerGroupIdent, &state);

    if(sksPullRequestStatus == UA_STATUSCODE_GOOD) {
        if(state == UA_PUBSUBSTATE_PREOPERATIONAL) {
            // 初次啟動
            UA_Server_setWriterGroupActivateKey(server, writerGroupIdent);
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔒 [初始化] 成功從 SKS 取得金鑰，啟動加密通道！");
        } else if (state == UA_PUBSUBSTATE_OPERATIONAL) {
            // 運行中發生 Key Rollover (10秒一到就會觸發這裡)
            UA_Server_setWriterGroupActivateKey(server, writerGroupIdent);
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔄 [金鑰輪替] 成功從 SKS 更新加密金鑰！");
        }
    } else {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ SKS 金鑰拉取失敗，錯誤碼: %s", UA_StatusCode_name(sksPullRequestStatus));
    }
}

static UA_ClientConfig *createSksClientConfig() {
    UA_ClientConfig *cc = (UA_ClientConfig *)UA_calloc(1, sizeof(UA_ClientConfig));
    UA_ClientConfig_setDefault(cc);

    UA_ByteString cert = loadFile("client_cert.der");
    UA_ByteString key = loadFile("client_key.der");
    
    // ✅ 修正 1：如果是自簽憑證，Client 必須直接信任 SKS Server 的憑證
    // 嘗試讀取 sks-cert.der 作為信任清單 (Trust List)
    UA_ByteString trust = loadFile("sks-server-certificate.der"); 

    cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    cc->securityPolicyUri = UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");

    // 將憑證與信任清單載入 Client 設置中
    UA_ClientConfig_setDefaultEncryption(cc, cert, key, &trust, 1, NULL, 0);


    UA_UserNameIdentityToken* identityToken = UA_UserNameIdentityToken_new();
    identityToken->userName = UA_STRING_ALLOC("SensorClient");
    identityToken->password = UA_STRING_ALLOC("ZtaTsnSecurePassword2026");
    cc->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
    cc->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN];
    cc->userIdentityToken.content.decoded.data = identityToken;

    UA_ByteString_clear(&cert); 
    UA_ByteString_clear(&key); 
    UA_ByteString_clear(&trust);
    return cc;
}

static void addWriterGroup(UA_Server *server) {
    UA_WriterGroupConfig writerGroupConfig;
    memset(&writerGroupConfig, 0, sizeof(UA_WriterGroupConfig));
    writerGroupConfig.name = UA_STRING("Demo WriterGroup");
    writerGroupConfig.publishingInterval = 1000;
    writerGroupConfig.writerGroupId = 100;
    writerGroupConfig.encodingMimeType = UA_PUBSUB_ENCODING_UADP;
    
    UA_UadpWriterGroupMessageDataType *writerGroupMessage = UA_UadpWriterGroupMessageDataType_new();
    writerGroupMessage->networkMessageContentMask = (UA_UadpNetworkMessageContentMask)(
        UA_UADPNETWORKMESSAGECONTENTMASK_PUBLISHERID | 
        UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER | 
        UA_UADPNETWORKMESSAGECONTENTMASK_WRITERGROUPID | 
        UA_UADPNETWORKMESSAGECONTENTMASK_PAYLOADHEADER |
        UA_UADPNETWORKMESSAGECONTENTMASK_TIMESTAMP |       // <--- 補上這個：帶上精確時間戳
        UA_UADPNETWORKMESSAGECONTENTMASK_SEQUENCENUMBER    // <--- 補上這個：帶上封包序號
    );
    writerGroupConfig.messageSettings.encoding = UA_EXTENSIONOBJECT_DECODED;
    writerGroupConfig.messageSettings.content.decoded.type = &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE];
    writerGroupConfig.messageSettings.content.decoded.data = writerGroupMessage;

    UA_ServerConfig *config = UA_Server_getConfig(server);
    writerGroupConfig.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    writerGroupConfig.securityGroupId = UA_STRING(DEMO_SECURITYGROUPNAME);
    writerGroupConfig.securityPolicy = &config->pubSubConfig.securityPolicies[0];

    UA_Server_addWriterGroup(server, connectionIdent, &writerGroupConfig, &writerGroupIdent);
    UA_UadpWriterGroupMessageDataType_delete(writerGroupMessage);

    UA_ClientConfig *sksClientConfig = createSksClientConfig();
    UA_Server_setSksClient(server, writerGroupConfig.securityGroupId, sksClientConfig,
                           SKS_SERVER_DISCOVERYURL, sksPullRequestCallback, NULL);
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

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4842, NULL);

    config->pubSubConfig.securityPolicies = (UA_PubSubSecurityPolicy *)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
    config->pubSubConfig.securityPoliciesSize = 1;
    UA_PubSubSecurityPolicy_Aes256Ctr(config->pubSubConfig.securityPolicies, config->logging);

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Double initialDistance = 0.0;
    UA_Variant_setScalar(&attr.value, &initialDistance, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "DistanceValue");
    attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    distanceNodeId = UA_NODEID_STRING(1, "DistanceValue");
    UA_Server_addVariableNode(server, distanceNodeId, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "Distance Sensor"), UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attr, NULL, NULL);

    UA_Server_addRepeatedCallback(server, (UA_ServerCallback)updateDistanceCallback, NULL, 1000, NULL);

    addPubSubConnection(server);
    addPublishedDataSet(server);
    addDataSetField(server);
    addWriterGroup(server);
    addDataSetWriter(server); 

    UA_Server_enableAllPubSubComponents(server);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Sensor Server 上線，等待 SKS 金鑰與 UDP 廣播中...");
    UA_Server_run(server, &running);

    UA_Server_delete(server);
    return 0;
}