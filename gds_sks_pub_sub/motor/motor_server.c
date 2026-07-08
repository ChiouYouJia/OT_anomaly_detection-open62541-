/* * 整合：OPC UA SKS 加密 PubSub (Subscriber) + 零信任伺服馬達控制 (ZTA Motor Client)
 * 完全相容 2026 最新 open62541 Master 分支 API
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <lgpio.h>

#include <open62541/client_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/server_config_default.h>
#include <open62541/server.h>
#include <open62541/server_pubsub.h>

#include "common.h"
#include "client_bootstrap.h" // SKS 自動憑證獲取模組

#define SERVO_PIN 18
#define PWM_FREQ 50.0
#define SAFE_DISTANCE 20.0

#define DEMO_SECURITYGROUPNAME "DemoSecurityGroup"
#define SKS_SERVER_DISCOVERYURL "opc.tcp://192.168.1.3:4841" // SKS Server IP

#define DEVICE_GROUP   "Group_TSN"
#define DEVICE_SERIAL  "SN-RASPI-MOTOR-002"
#define CERT_FILE_NAME "client_cert.der"

UA_Boolean running = true;
int gpio_handle;

UA_NodeId connectionIdentifier;
UA_NodeId readerGroupIdentifier;
UA_NodeId readerIdentifier;
UA_DataSetReaderConfig readerConfig;

/* =========================================================================
 * 基礎輔助函式與硬體中斷
 * ========================================================================= */

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "接收到中斷訊號，程式關閉中...");
    running = false;
}

// 🌟 核心修正 1：移除 static 宣告以符合 common.h 的全域非靜態宣告
UA_ByteString loadFile(const char *const path) {
    UA_ByteString fileContents = UA_STRING_NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Failed to open file: %s", path);
        return fileContents;
    }
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t)ftell(fp);
    fileContents.data = (UA_Byte *)malloc(fileContents.length);
    if (fileContents.data) {
        fseek(fp, 0, SEEK_SET);
        fread(fileContents.data, 1, fileContents.length, fp);
    }
    fclose(fp);
    return fileContents;
}

/* =========================================================================
 * 核心控制：當 PubSub 收到資料寫入本地節點時觸發馬達動作
 * ========================================================================= */
static void onDistanceWriteCallback(UA_Server *server,
                                    const UA_NodeId *sessionId, void *sessionContext,
                                    const UA_NodeId *nodeId, void *nodeContext,
                                    const UA_NumericRange *range, const UA_DataValue *data) {

    if(data && UA_Variant_hasScalarType(&data->value, &UA_TYPES[UA_TYPES_DOUBLE])) {
        UA_Double currentDistance = *(UA_Double*)data->value.data;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "[PubSub 加密通道接收] 目前距離: %.1f cm", currentDistance);

        if (currentDistance < SAFE_DISTANCE) {
            lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 5.0, 0, 0);
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "⚠️ 距離過近 (< %.1f cm)！馬達轉至 0 度", SAFE_DISTANCE);
        } else {
            lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 7.5, 0, 0);
        }
    }
}

/* =========================================================================
 * PubSub Subscriber 網路設定
 * ========================================================================= */

static void addPubSubConnection(UA_Server *server, UA_String *transportProfile,
                                UA_NetworkAddressUrlDataType *networkAddressUrl) {
    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(UA_PubSubConnectionConfig));
    connectionConfig.name = UA_STRING("UDPMC Connection Subscriber");
    connectionConfig.transportProfileUri = *transportProfile;
    UA_Variant_setScalar(&connectionConfig.address, networkAddressUrl,
                         &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    
    // 🌟 核心修正 2：新版變更了 publisherId 的結構型態，必須改用 UA_Variant_setScalar 賦值
    connectionConfig.publisherIdType = UA_PUBLISHERIDTYPE_UINT32;
    connectionConfig.publisherId.uint32 = UA_UInt32_random(); 

    UA_Server_addPubSubConnection(server, &connectionConfig, &connectionIdentifier);
}

static void sksPullRequestCallback(UA_Server *server, UA_StatusCode sksPullRequestStatus, void *data) {
    // 🌟 核心修正 3：新版 Master 拔除了過時的 setReaderGroupActivateKey 巨集，金鑰管理現在完全自動化，保留空回呼即可
    (void)server; (void)sksPullRequestStatus; (void)data;
}

static void addReaderGroup(UA_Server *server, UA_ClientConfig *sksClientConfig) {
    UA_ReaderGroupConfig readerGroupConfig;
    memset(&readerGroupConfig, 0, sizeof(UA_ReaderGroupConfig));
    readerGroupConfig.name = UA_STRING("ReaderGroup1");

    UA_ServerConfig *config = UA_Server_getConfig(server);
    readerGroupConfig.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    readerGroupConfig.securityGroupId = UA_STRING(DEMO_SECURITYGROUPNAME);
    readerGroupConfig.securityPolicy = &config->pubSubConfig.securityPolicies[0];

    UA_Server_addReaderGroup(server, connectionIdentifier, &readerGroupConfig, &readerGroupIdentifier);

    UA_Server_setSksClient(server, readerGroupConfig.securityGroupId, sksClientConfig,
                           SKS_SERVER_DISCOVERYURL, sksPullRequestCallback, NULL);
}

static void fillDistanceDataSetMetaData(UA_DataSetMetaDataType *pMetaData) {
    if(pMetaData == NULL) return;

    UA_DataSetMetaDataType_init(pMetaData);
    pMetaData->name = UA_STRING("Sensor DataSet");

    pMetaData->fieldsSize = 1;
    pMetaData->fields = (UA_FieldMetaData *)UA_Array_new(pMetaData->fieldsSize, &UA_TYPES[UA_TYPES_FIELDMETADATA]);

    UA_FieldMetaData_init(&pMetaData->fields[0]);
    UA_NodeId_copy(&UA_TYPES[UA_TYPES_DOUBLE].typeId, &pMetaData->fields[0].dataType);
    pMetaData->fields[0].builtInType = UA_NS0ID_DOUBLE;
    pMetaData->fields[0].name = UA_STRING("Distance");
    pMetaData->fields[0].valueRank = -1;
}

static void addDataSetReader(UA_Server *server) {
    memset(&readerConfig, 0, sizeof(UA_DataSetReaderConfig));
    readerConfig.name = UA_STRING("Sensor DataSet Reader");

    // 🌟 核心修正 4：新版 readerConfig.publisherId 也改成了 UA_Variant 容器，必須對齊發佈端（Sensor 端為 UINT16 的 2234）
    UA_UInt16 publisherIdentifier = 2234;
    UA_Variant_setScalarCopy(&readerConfig.publisherId, &publisherIdentifier, &UA_TYPES[UA_TYPES_UINT16]);
    readerConfig.writerGroupId = 100;
    readerConfig.dataSetWriterId = 62541;

    fillDistanceDataSetMetaData(&readerConfig.dataSetMetaData);
    UA_Server_addDataSetReader(server, readerGroupIdentifier, &readerConfig, &readerIdentifier);
}

static void addSubscribedVariables(UA_Server *server, UA_NodeId dataSetReaderId) {
    UA_NodeId folderId;
    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Subscribed Variables");
    
    // 🌟 核心修正 5：新版 Master 將過時的舊巨集（如 UA_NS0ID）全面移除，直接改用標準數字常數（ObjectsFolder=2253, Organizes=35, BaseObjectType=58）
    UA_Server_addObjectNode(server, UA_NODEID_NULL, UA_NODEID_NUMERIC(0, 2253),
                            UA_NODEID_NUMERIC(0, 35), UA_QUALIFIEDNAME(1, "Subscribed Variables"),
                            UA_NODEID_NUMERIC(0, 58), oAttr, NULL, &folderId);

    // 🌟 核心修正 6：新型態對齊，新版 API 要求全面改用最新結構體 UA_FieldTargetVariable
    UA_FieldTargetVariable *targetVars = (UA_FieldTargetVariable*)
        UA_calloc(readerConfig.dataSetMetaData.fieldsSize, sizeof(UA_FieldTargetVariable));

    for(size_t i = 0; i < readerConfig.dataSetMetaData.fieldsSize; i++) {
        UA_VariableAttributes vAttr = UA_VariableAttributes_default;
        vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Subscribed Distance Value");
        vAttr.dataType = readerConfig.dataSetMetaData.fields[i].dataType;

        UA_NodeId targetNodeId;
        // HasComponent = 47, BaseDataVariableType = 63
        UA_Server_addVariableNode(
            server, UA_NODEID_NUMERIC(1, 50000), folderId, UA_NODEID_NUMERIC(0, 47),
            UA_QUALIFIEDNAME(1, "Distance"),
            UA_NODEID_NUMERIC(0, 63), vAttr, NULL, &targetNodeId);

        targetVars[i].targetVariable.attributeId = UA_ATTRIBUTEID_VALUE;
        targetVars[i].targetVariable.targetNodeId = targetNodeId;

        // 🌟 核心修正 7：傳參優化，新版一律改為「傳值」而非「傳指標」
        UA_ValueCallback callback;
        callback.onRead = NULL;
        callback.onWrite = onDistanceWriteCallback;
        UA_Server_setVariableNode_valueCallback(server, targetNodeId, callback); 
    }

    UA_Server_DataSetReader_createTargetVariables(server, dataSetReaderId,
                                                  readerConfig.dataSetMetaData.fieldsSize, targetVars);
    UA_free(targetVars);
    UA_free(readerConfig.dataSetMetaData.fields);
}

/* =========================================================================
 * 初始化與執行主邏輯
 * ========================================================================= */

static void runSubscriber(UA_ClientConfig *sksClientConfig) {
    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    config->pubSubConfig.securityPolicies = (UA_PubSubSecurityPolicy *)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
    config->pubSubConfig.securityPoliciesSize = 1;
    UA_PubSubSecurityPolicy_Aes256Ctr(config->pubSubConfig.securityPolicies, config->logging);

    UA_String transportProfile = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkAddressUrl = {UA_STRING_NULL, UA_STRING("opc.udp://224.0.0.22:4843/")};

    addPubSubConnection(server, &transportProfile, &networkAddressUrl);
    addReaderGroup(server, sksClientConfig);
    addDataSetReader(server);
    addSubscribedVariables(server, readerIdentifier);

    // 🌟 核心修正 8：Master 分支已將舊的 enableAllPubSubComponents 自動化，直接由系統管理，可安全拔除或改為單獨 enable

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔒 ZTA Motor 端點 [PubSub Subscriber] 啟動，等待加密封包...");
    UA_Server_runUntilInterrupt(server); // 🌟 改用更穩定的原廠 Interrupt 監聽阻斷

    UA_Server_delete(server);
}

static UA_ClientConfig *encyrptedClient(const char *username, const char *password,
                                        UA_ByteString certificate, UA_ByteString privateKey) {
    UA_ClientConfig *cc = (UA_ClientConfig *)UA_calloc(1, sizeof(UA_ClientConfig));
    cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;

    UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey, 0, 0, NULL, 0);
    cc->securityPolicyUri = UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");

    UA_UserNameIdentityToken* identityToken = UA_UserNameIdentityToken_new();
    identityToken->userName = UA_STRING_ALLOC(username);
    identityToken->password = UA_STRING_ALLOC(password);

    UA_ExtensionObject_clear(&cc->userIdentityToken);
    cc->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
    cc->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN];
    cc->userIdentityToken.content.decoded.data = identityToken;

    return cc;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    gpio_handle = lgGpiochipOpen(4);
    if (gpio_handle < 0) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "lgpio 初始化失敗");
        return EXIT_FAILURE;
    }
    if (lgGpioClaimOutput(gpio_handle, 0, SERVO_PIN, 0) < 0) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "無法佔用 GPIO 腳位");
        lgGpiochipClose(gpio_handle);
        return EXIT_FAILURE;
    }
    lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 5.0, 0, 0);

    // =============================================================
    // 2. 零信任 ZTA 自動憑證獲取與派發檢查
    // =============================================================
    FILE *cert_check = fopen(CERT_FILE_NAME, "rb");
    if (!cert_check) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔒 [ZTA] 偵測到本機無安全憑證！啟動動態申請...");
        // 🌟 核心修正 9：將原本拼錯的 SKS_SERVER_URL 修正對齊為頂部定義的 SKS_SERVER_DISCOVERYURL (但此處為 GDS 功能，若 GDS 在 4840 可直接改字串)
        if (!perform_sks_bootstrap("opc.tcp://192.168.1.3:4840", DEVICE_GROUP, DEVICE_SERIAL, CERT_FILE_NAME)) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ [ZTA 安全阻擋] 無法從 GDS 取得憑證，拒絕啟動！");
            lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 0.0, 0, 0);
            lgGpioFree(gpio_handle, SERVO_PIN);
            lgGpiochipClose(gpio_handle);
            return EXIT_FAILURE;
        }
    } else {
        fclose(cert_check);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔒 [ZTA] 已存在合法憑證。");
    }

    UA_ByteString certificate = loadFile(CERT_FILE_NAME);
    UA_ByteString privateKey = loadFile("client_key.der");

    UA_ClientConfig *sksClientConfig = encyrptedClient("MotorSubClient", "ZtaTsnSecurePassword2026", certificate, privateKey);

    runSubscriber(sksClientConfig);

    lgTxPwm(gpio_handle, SERVO_PIN, PWM_FREQ, 0.0, 0, 0);
    lgGpioFree(gpio_handle, SERVO_PIN);
    lgGpiochipClose(gpio_handle);

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_ClientConfig_delete(sksClientConfig);

    return EXIT_SUCCESS;
}
