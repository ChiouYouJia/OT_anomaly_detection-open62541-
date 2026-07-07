#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/client_config_default.h> // 確保引入這個
#include <open62541/server_config_default.h>
#include <open62541/server.h>
#include <open62541/server_pubsub.h>
#include <lgpio.h>

#define SERVO_PIN 18
#define PWM_FREQ 50.0
#define SAFE_DISTANCE 20.0
#define DEMO_SECURITYGROUPNAME "DemoSecurityGroup"
#define SKS_SERVER_DISCOVERYURL "opc.tcp://127.0.0.1:4841"

UA_Boolean running = true;
int gpio_handle = -1;
UA_NodeId connectionIdentifier, readerGroupIdentifier, readerIdentifier;

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

static void onDistanceDataChange(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, const UA_NodeId *nodeId, void *nodeContext, const UA_NumericRange *range, const UA_DataValue *value) {
    if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DOUBLE])) {
        UA_Double currentDistance = *(UA_Double*)value->value.data;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "📥 [SKS解密成功] 收到距離: %.1f cm", currentDistance);
        if (gpio_handle >= 0) {
            lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, (currentDistance < SAFE_DISTANCE) ? 5.0 : 7.5, 0, 0);
        }
    }
}

static void sksPullRequestCallback(UA_Server *server, UA_StatusCode sksPullRequestStatus, void *data) {
    UA_PubSubState state = UA_PUBSUBSTATE_OPERATIONAL;
    // 先確認目前的 ReaderGroup 狀態
    UA_Server_ReaderGroup_getState(server, readerGroupIdentifier, &state);
    
    if(sksPullRequestStatus == UA_STATUSCODE_GOOD) {
        if (state == UA_PUBSUBSTATE_PREOPERATIONAL) {
            // 初次啟動
            UA_Server_setReaderGroupActivateKey(server, readerGroupIdentifier);
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔑 [初始化] SKS 金鑰已部署，並成功載入解密引擎！");
        } else if (state == UA_PUBSUBSTATE_OPERATIONAL) {
            // 運行中發生 Key Rollover
            UA_Server_setReaderGroupActivateKey(server, readerGroupIdentifier);
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔄 [金鑰輪替] 已成功向 SKS 獲取並更新為新金鑰！");
        }
    } else {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ SKS 金鑰拉取失敗，錯誤碼: %s", UA_StatusCode_name(sksPullRequestStatus));
    }
}

static UA_ClientConfig *createSksClientConfig() {
    UA_ClientConfig *cc = (UA_ClientConfig *)UA_calloc(1, sizeof(UA_ClientConfig));
    UA_ClientConfig_setDefault(cc); // 補上初始化
    UA_ByteString cert = loadFile("client_cert.der");
    UA_ByteString key = loadFile("client_key.der");
    UA_ByteString trust = loadFile("sks-server-certificate.der");

    // 若編譯庫沒包含加密，這行會報錯，記得確保編譯參數
    UA_ClientConfig_setDefaultEncryption(cc, cert, key, &trust, 1, NULL, 0);
    cc->securityPolicyUri = UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");

    UA_UserNameIdentityToken* identityToken = UA_UserNameIdentityToken_new();
    identityToken->userName = UA_STRING_ALLOC("MotorSubClient");
    identityToken->password = UA_STRING_ALLOC("ZtaTsnSecurePassword2026");
    cc->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
    cc->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN];
    cc->userIdentityToken.content.decoded.data = identityToken;

    UA_ByteString_clear(&cert); UA_ByteString_clear(&key); UA_ByteString_clear(&trust);
    return cc;
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4801, NULL);

    config->pubSubConfig.securityPolicies = (UA_PubSubSecurityPolicy*)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
    config->pubSubConfig.securityPoliciesSize = 1;
    UA_PubSubSecurityPolicy_Aes256Ctr(config->pubSubConfig.securityPolicies, config->logging);

    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("UDP Connection");
    connectionConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkAddressUrl = {UA_STRING_NULL, UA_STRING("opc.udp://127.0.0.1:4843/")};
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    UA_Server_addPubSubConnection(server, &connectionConfig, &connectionIdentifier);

    UA_ReaderGroupConfig readerGroupConfig;
    memset(&readerGroupConfig, 0, sizeof(UA_ReaderGroupConfig));
    readerGroupConfig.name = UA_STRING("ReaderGroup1");
    readerGroupConfig.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    readerGroupConfig.securityGroupId = UA_STRING(DEMO_SECURITYGROUPNAME);
    readerGroupConfig.securityPolicy = &config->pubSubConfig.securityPolicies[0];
    UA_Server_addReaderGroup(server, connectionIdentifier, &readerGroupConfig, &readerGroupIdentifier);

    UA_ClientConfig *sksClientConfig = createSksClientConfig();
    UA_Server_setSksClient(server, readerGroupConfig.securityGroupId, sksClientConfig,
                           SKS_SERVER_DISCOVERYURL, sksPullRequestCallback, NULL);

    UA_DataSetReaderConfig readerConfig;
    memset(&readerConfig, 0, sizeof(UA_DataSetReaderConfig));
    // ✅ 1. 必須要給名字，否則加入資訊模型會失敗
    readerConfig.name = UA_STRING("Demo DataSetReader"); 
    
    readerConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    readerConfig.publisherId.id.uint16 = 2234;
    readerConfig.writerGroupId = 100;
    readerConfig.dataSetWriterId = 62541;

    // ✅ 2. 必須設定 Metadata，告訴 Reader 如何解碼 UDP 封包
    UA_DataSetMetaDataType *pMetaData = &readerConfig.dataSetMetaData;
    UA_DataSetMetaDataType_init(pMetaData);
    pMetaData->name = UA_STRING("Demo PDS");
    pMetaData->fieldsSize = 1; // 裡面只有一個欄位
    pMetaData->fields = (UA_FieldMetaData*)UA_Array_new(1, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
    
    UA_FieldMetaData_init(&pMetaData->fields[0]);
    UA_NodeId_copy(&UA_TYPES[UA_TYPES_DOUBLE].typeId, &pMetaData->fields[0].dataType);
    pMetaData->fields[0].builtInType = UA_NS0ID_DOUBLE; // 型態是 Double
    pMetaData->fields[0].name = UA_STRING("Sensor Distance");
    pMetaData->fields[0].valueRank = -1; // 標量 (Scalar)
    UA_Server_addDataSetReader(server, readerGroupIdentifier, &readerConfig, &readerIdentifier);

    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    vAttr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    UA_NodeId targetNode = UA_NODEID_NULL;
    UA_Server_addVariableNode(server, targetNode, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1, "LocalDistance"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), vAttr, NULL, &targetNode);

    UA_FieldTargetDataType targetVar;
    memset(&targetVar, 0, sizeof(targetVar));
    targetVar.attributeId = UA_ATTRIBUTEID_VALUE;
    targetVar.targetNodeId = targetNode;
    UA_Server_DataSetReader_createTargetVariables(server, readerIdentifier, 1, &targetVar);
    UA_ValueCallback callback;
    // 2. 初始化它
    callback.onRead = NULL;
    callback.onWrite = onDistanceDataChange;
    
    // 3. 傳入結構的指標
    UA_Server_setVariableNode_valueCallback(server, targetNode, callback);

    UA_Server_enableAllPubSubComponents(server);
    UA_Server_run(server, &running);
    UA_Server_delete(server);
    return 0;
}