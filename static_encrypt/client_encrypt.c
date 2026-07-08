#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/server_config_default.h>
#include <open62541/server.h>
#include <open62541/server_pubsub.h>
#include <lgpio.h>

#define SERVO_PIN 18
#define PWM_FREQ 50.0
#define SAFE_DISTANCE 20.0

// ================= [新增：靜態加密金鑰定義] =================
#define UA_AES128CTR_SIGNING_KEY_LENGTH 32
#define UA_AES128CTR_KEY_LENGTH 16
#define UA_AES128CTR_KEYNONCE_LENGTH 4

// 必須與 Sensor 端完全一致
static UA_Byte signingKey[UA_AES128CTR_SIGNING_KEY_LENGTH] = {0};
static UA_Byte encryptingKey[UA_AES128CTR_KEY_LENGTH] = {0};
static UA_Byte keyNonce[UA_AES128CTR_KEYNONCE_LENGTH] = {0};
// =========================================================

UA_Boolean running = true;
int gpio_handle = -1;
UA_NodeId connectionIdentifier, readerGroupIdentifier, readerIdentifier;

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "收到中斷訊號，正在關閉...");
    running = false;
}

// 接收到資料時觸發馬達的 Callback
static void onDistanceDataChange(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, const UA_NodeId *nodeId, void *nodeContext, const UA_NumericRange *range, const UA_DataValue *value) {
    if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DOUBLE])) {
        UA_Double currentDistance = *(UA_Double*)value->value.data;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔒 [解密成功] 收到加密 UDP 距離: %.1f cm", currentDistance);

        if (gpio_handle >= 0) {
            if (currentDistance < SAFE_DISTANCE) {
                lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 5.0, 0, 0);
                UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "⚠️ 距離過近！馬達轉至 0 度");
            } else {
                lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 7.5, 0, 0);
                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "✅ 距離安全，馬達轉至 90 度");
            }
        }
    }
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    // GPIO 初始化
    gpio_handle = lgGpiochipOpen(4);
    if (gpio_handle >= 0) {
        lgGpioClaimOutput(gpio_handle, 0, SERVO_PIN, 0);
        lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 5.0, 0, 0);
    } else {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "GPIO 初始化失敗 (無硬體環境，僅印出 Log)");
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4801, NULL);

    // ================= [關鍵修改：註冊加密演算法] =================
    config->pubSubConfig.securityPolicies = (UA_PubSubSecurityPolicy*)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
    config->pubSubConfig.securityPoliciesSize = 1;
    UA_PubSubSecurityPolicy_Aes128Ctr(config->pubSubConfig.securityPolicies, config->logging);
    // =========================================================

    // 設定 PubSub 連線
    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("UDP Connection");
    connectionConfig.transportProfileUri = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkAddressUrl = {UA_STRING_NULL, UA_STRING("opc.udp://127.0.0.1:4843/")};
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    UA_Server_addPubSubConnection(server, &connectionConfig, &connectionIdentifier);

    // 設定 ReaderGroup
    UA_ReaderGroupConfig readerGroupConfig;
    memset(&readerGroupConfig, 0, sizeof(UA_ReaderGroupConfig));
    readerGroupConfig.name = UA_STRING("ReaderGroup1");
    
    // ================= [關鍵修改：啟用加密並注入金鑰] =================
    readerGroupConfig.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT; 
    readerGroupConfig.securityPolicy = &config->pubSubConfig.securityPolicies[0];
    UA_Server_addReaderGroup(server, connectionIdentifier, &readerGroupConfig, &readerGroupIdentifier);

    UA_ByteString sk = {UA_AES128CTR_SIGNING_KEY_LENGTH, signingKey};
    UA_ByteString ek = {UA_AES128CTR_KEY_LENGTH, encryptingKey};
    UA_ByteString kn = {UA_AES128CTR_KEYNONCE_LENGTH, keyNonce};
    UA_Server_setReaderGroupEncryptionKeys(server, readerGroupIdentifier, 1, sk, ek, kn);
    // =========================================================

    // 嚴格對齊 Tutorial 的 MetaData
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
    // 💡 賦予 NULL NodeId，告訴底層略過型別嚴格檢查
    readerConfig.dataSetMetaData.fields[0].dataType = UA_NODEID_NULL;
    readerConfig.dataSetMetaData.fields[0].builtInType = 0; 
    readerConfig.dataSetMetaData.fields[0].valueRank = UA_VALUERANK_ANY;
    UA_Server_addDataSetReader(server, readerGroupIdentifier, &readerConfig, &readerIdentifier);

    // 精準建立承接用的變數
    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "LocalDistance");
    vAttr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    vAttr.valueRank = -1; 
    UA_Double initVal = 0.0;
    UA_Variant_setScalar(&vAttr.value, &initVal, &UA_TYPES[UA_TYPES_DOUBLE]); 

    UA_NodeId targetNode = UA_NODEID_NULL; 
    UA_Server_addVariableNode(server, targetNode, 
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), 
                              UA_QUALIFIEDNAME(1, "LocalDistance"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), 
                              vAttr, NULL, &targetNode); 

    UA_FieldTargetDataType targetVar;
    memset(&targetVar, 0, sizeof(targetVar));
    targetVar.attributeId = UA_ATTRIBUTEID_VALUE;
    targetVar.targetNodeId = targetNode; 
    UA_Server_DataSetReader_createTargetVariables(server, readerIdentifier, 1, &targetVar);

    UA_ValueCallback callback = {NULL, onDistanceDataChange};
    UA_Server_setVariableNode_valueCallback(server, targetNode, callback);
    UA_free(readerConfig.dataSetMetaData.fields);

    // 強制啟動所有 PubSub 組件
    UA_Server_enableAllPubSubComponents(server);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Motor Sub 端啟動，準備接收並解密 AES-128-CTR UDP 資料...");
    UA_Server_run(server, &running);

    if (gpio_handle >= 0) {
        lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 0.0, 0, 0);
        lgGpioFree(gpio_handle, SERVO_PIN);
        lgGpiochipClose(gpio_handle);
    }
    UA_Server_delete(server);
    return EXIT_SUCCESS;
}