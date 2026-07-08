/* * 整合：OPC UA SKS 加密 PubSub + 零信任感測器伺服器 (ZTA Sensor Server)
 */

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
#include <open62541/plugin/accesscontrol_default.h>
#include "common.h"
#include "client_bootstrap.h" // 🌟 引入分離出來的零信任驗證模組

#define DEMO_SECURITYGROUPNAME "DemoSecurityGroup"
#define SKS_SERVER_DISCOVERYURL "opc.tcp://192.168.1.3:4841"

UA_Boolean running = true;
UA_NodeId distanceNodeId;
double read_distance(void);
UA_NodeId connectionIdent, publishedDataSetIdent, writerGroupIdent;

/* =========================================================================
 * 基礎輔助函式與 Sensor 邏輯
 * ========================================================================= */
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

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Received Ctrl-C");
    running = false;
}

double read_distance(void){
    double min = 2.0;
    double max = 50.0;
    double distance = min + ((double)rand() / (RAND_MAX / (max - min)));
    return distance;
}

static void updateDistanceCallback(UA_Server *server, void *data) {
    UA_Double distance = read_distance();
    if (distance > 0) {
        UA_Variant value;
        UA_Variant_setScalar(&value, &distance, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, distanceNodeId, value);
    }
}

/* =========================================================================
 * PubSub 網路與資料集設定區塊
 * ========================================================================= */

static void addPubSubConnection(UA_Server *server, UA_String *transportProfile,
                                UA_NetworkAddressUrlDataType *networkAddressUrl) {
    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("UADP Connection 1");
    connectionConfig.transportProfileUri = *transportProfile;
    UA_Variant_setScalar(&connectionConfig.address, networkAddressUrl,
                         &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
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
    UA_NodeId dataSetFieldIdent;
    UA_DataSetFieldConfig dataSetFieldConfig;
    memset(&dataSetFieldConfig, 0, sizeof(UA_DataSetFieldConfig));
    dataSetFieldConfig.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    dataSetFieldConfig.field.variable.fieldNameAlias = UA_STRING("Sensor Distance");
    dataSetFieldConfig.field.variable.promotedField = UA_FALSE;
    
    // 🌟 修改：將原本發佈 ServerTime 改為發佈我們的 distanceNodeId
    dataSetFieldConfig.field.variable.publishParameters.publishedVariable = distanceNodeId;
    dataSetFieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    
    UA_Server_addDataSetField(server, publishedDataSetIdent, &dataSetFieldConfig, &dataSetFieldIdent);
}

static void sksPullRequestCallback(UA_Server *server, UA_StatusCode sksPullRequestStatus, void *data) {
    UA_PubSubState state = UA_PUBSUBSTATE_OPERATIONAL;
    UA_Server_WriterGroup_getState(server, writerGroupIdent, &state);
    if(sksPullRequestStatus == UA_STATUSCODE_GOOD && state == UA_PUBSUBSTATE_PREOPERATIONAL)
        UA_Server_setWriterGroupActivateKey(server, writerGroupIdent);
}

static void addWriterGroup(UA_Server *server, UA_ClientConfig *sksClientConfig) {
    UA_WriterGroupConfig writerGroupConfig;
    memset(&writerGroupConfig, 0, sizeof(UA_WriterGroupConfig));
    writerGroupConfig.name = UA_STRING("Demo WriterGroup");
    writerGroupConfig.publishingInterval = 100;
    writerGroupConfig.writerGroupId = 100;
    writerGroupConfig.encodingMimeType = UA_PUBSUB_ENCODING_UADP;
    writerGroupConfig.messageSettings.encoding = UA_EXTENSIONOBJECT_DECODED;
    writerGroupConfig.messageSettings.content.decoded.type =
        &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE];

    // Encryption settings for PubSub
    writerGroupConfig.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    writerGroupConfig.securityGroupId = UA_STRING(DEMO_SECURITYGROUPNAME);
    
    UA_ServerConfig *config = UA_Server_getConfig(server);
    writerGroupConfig.securityPolicy = &config->pubSubConfig.securityPolicies[0];

    UA_UadpWriterGroupMessageDataType *writerGroupMessage = UA_UadpWriterGroupMessageDataType_new();
    writerGroupMessage->networkMessageContentMask =
        (UA_UadpNetworkMessageContentMask)(UA_UADPNETWORKMESSAGECONTENTMASK_PUBLISHERID |
                                           UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER |
                                           UA_UADPNETWORKMESSAGECONTENTMASK_WRITERGROUPID |
                                           UA_UADPNETWORKMESSAGECONTENTMASK_PAYLOADHEADER);
    writerGroupConfig.messageSettings.content.decoded.data = writerGroupMessage;
    
    UA_Server_addWriterGroup(server, connectionIdent, &writerGroupConfig, &writerGroupIdent);
    UA_Server_enableWriterGroup(server, writerGroupIdent);
    UA_UadpWriterGroupMessageDataType_delete(writerGroupMessage);

    // Fetch initial set of keys for PubSub
    UA_Server_setSksClient(server, writerGroupConfig.securityGroupId, sksClientConfig,
                           SKS_SERVER_DISCOVERYURL, sksPullRequestCallback, NULL);
}

static void addDataSetWriter(UA_Server *server) {
    UA_NodeId dataSetWriterIdent;
    UA_DataSetWriterConfig dataSetWriterConfig;
    memset(&dataSetWriterConfig, 0, sizeof(UA_DataSetWriterConfig));
    dataSetWriterConfig.name = UA_STRING("Demo DataSetWriter");
    dataSetWriterConfig.dataSetWriterId = 62541;
    dataSetWriterConfig.keyFrameCount = 10;
    UA_Server_addDataSetWriter(server, writerGroupIdent, publishedDataSetIdent,
                               &dataSetWriterConfig, &dataSetWriterIdent);
}

/* =========================================================================
 * 核心 Server 運行邏輯 (整併 ZTA 防禦與 PubSub)
 * ========================================================================= */

static void run(UA_UInt16 port, UA_String *transportProfile,
                UA_NetworkAddressUrlDataType *networkAddressUrl, UA_ClientConfig *sksClientConfig) {
    
    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    // ================= [ZTA 伺服器安全設定區塊開始] =================
    UA_ByteString certificate = loadFile("sensor_operational_cert.der");
    UA_ByteString privateKey = loadFile("client_key.der");
    UA_ByteString trustList[1];
    trustList[0] = loadFile("ca_cert.der"); 
    UA_ByteString issuerList[1];
    issuerList[0] = loadFile("ca_cert.der");

    if(certificate.length == 0 || privateKey.length == 0 || trustList[0].length == 0) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ [安全防禦] 營運憑證、私鑰或信任清單載入失敗！防禦性阻斷服務啟動。");
        UA_Server_delete(server);
        return;
    }

    UA_ServerConfig_setDefaultWithSecurityPolicies(config, port,
                                                   &certificate, &privateKey,
                                                   trustList, 1, issuerList, 1, NULL, 0);
    config->applicationDescription.applicationUri = UA_STRING_ALLOC("urn:open62541.zta.sensor");

    // 關閉匿名登入，設定 ZTA 專用工控帳密
    static const UA_UsernamePasswordLogin defaultLogins[1] = {
        {UA_STRING_STATIC("MotorSubClient"), UA_STRING_STATIC("ZtaTsnSecurePassword2026")}
    };
    UA_String securityPolicyUri = config->securityPolicies[config->securityPoliciesSize-1].policyUri;
    config->accessControl.clear(&config->accessControl);
    UA_AccessControl_default(config, false, &securityPolicyUri, 1, defaultLogins);

    // 強制拔除/改寫不安全的 None (明文) 端點
    for(size_t i = 0; i < config->endpointsSize; i++) {
        if(config->endpoints[i].securityMode == UA_MESSAGESECURITYMODE_NONE) {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "🔒 [ZTA 防禦] 自動裁撤不安全的 None 明文端點: %.*s",
                           (int)config->endpoints[i].endpointUrl.length, config->endpoints[i].endpointUrl.data);
            config->endpoints[i].securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        }
    }
    // ================= [ZTA 伺服器安全設定區塊結束] =================

    // ================= [感測器資料節點設定區塊] =================
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Double initialDistance = 0.0;
    UA_Variant_setScalar(&attr.value, &initialDistance, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.description = UA_LOCALIZEDTEXT("en-US", "Ultrasonic Distance Sensor Value");
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "DistanceValue");
    attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;

    UA_NodeId myNodeId = UA_NODEID_STRING(1, "DistanceValue");
    UA_QualifiedName myName = UA_QUALIFIEDNAME(1, "Distance Sensor");
    
    UA_Server_addVariableNode(server, myNodeId, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), myName,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              attr, NULL, &distanceNodeId);

    // 設定週期性任務 (2秒更新一次 Sensor 資料)
    UA_Server_addRepeatedCallback(server, (UA_ServerCallback)updateDistanceCallback, NULL, 2000, NULL);

    // ================= [PubSub 加密與通訊設定區塊] =================
    config->pubSubConfig.securityPolicies = (UA_PubSubSecurityPolicy *)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
    config->pubSubConfig.securityPoliciesSize = 1;
    UA_PubSubSecurityPolicy_Aes256Ctr(config->pubSubConfig.securityPolicies, config->logging);

    addPubSubConnection(server, transportProfile, networkAddressUrl);
    addPublishedDataSet(server);
    addDataSetField(server); // 這裡已經綁定 distanceNodeId
    addWriterGroup(server, sksClientConfig);
    addDataSetWriter(server);

    UA_Server_enableAllPubSubComponents(server);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔒 Sensor Server [零信任全域防禦模式 + Encrypted PubSub] 上線，監聽通訊埠: %d", port);
    
    UA_Server_run(server, &running);

    // 資源釋放
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_ByteString_clear(&trustList[0]);
    UA_ClientConfig_delete(sksClientConfig);
    UA_Server_delete(server);
}

/* =========================================================================
 * 產生向 SKS 拉取 PubSub 金鑰專用的加密 Client
 * ========================================================================= */
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
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);
    srand(time(NULL));

    // =============================================================
    // 🌟 第一階段：零信任 Bootstrap 驗證 (伺服器自身憑證)
    // =============================================================
    const char* cert_path = "sensor_operational_cert.der";
    UA_Boolean need_bootstrap = true;

    FILE *cert_fp = fopen(cert_path, "rb");
    if (cert_fp) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "ℹ️ 偵測到本地已存在營運憑證，嘗試直接載入...");
        fclose(cert_fp);
        need_bootstrap = false; 
    }
/*
    if (need_bootstrap) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "📡 本地無憑證，啟動零信任向 GDS 申請憑證...");
        // 這裡的 IP 可視你的架構調整，或寫死為 localhost / 網域
        const char* gds_url = "opc.tcp://192.168.1.3:4840"; 
        UA_Boolean boot_success = perform_sks_bootstrap(gds_url, "Group_TSN", "SN-RASPI-SENSOR-001", cert_path);

        if(!boot_success) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ [安全防禦] 設備未通過零信任審查，拒絕啟動服務！");
            return EXIT_FAILURE;
        }
    }
*/
    // =============================================================
    // 🌟 第二階段：設定 PubSub 的網路位置與 SKS Client
    // =============================================================
    UA_String transportProfile = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType networkAddressUrl = {UA_STRING_NULL, UA_STRING("opc.udp://224.0.0.22:4843/")};
    UA_UInt16 port = 4842;

    // 這裡我們直接複用剛 Bootstrap 取得的憑證來作為 SKS PubSub Client 的身分證明
    // (如果你的架構中 Client 需要不同的憑證，可於此處改讀別的檔案)
    UA_ByteString clientCert = loadFile("sensor_operational_cert.der");
    UA_ByteString clientKey  = loadFile("client_key.der");

    // 產生負責定期去 SKS 拉取 PubSub Symmetric Keys 的內部 Client
    UA_ClientConfig *sksClientConfig = encyrptedClient("user1", "password", clientCert, clientKey);

    // 啟動整合後的 Server
    run(port, &transportProfile, &networkAddressUrl, sksClientConfig);

    UA_ByteString_clear(&clientCert);
    UA_ByteString_clear(&clientKey);

    return 0;
}
