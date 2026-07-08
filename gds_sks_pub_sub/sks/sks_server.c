/* * * 專屬 SKS (PubSub 金鑰派發中心) - 零信任架構版
 */

#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <stdlib.h>
#include <stdio.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/server_pubsub.h>
#include "common.h"

// 金鑰輪轉與群組設定
#define DEMO_KEYLIFETIME_MINUTES 10
#define DEMO_MAXFUTUREKEYCOUNT 1
#define DEMO_MAXPASTKEYCOUNT 1
#define DEMO_SECURITYGROUPNAME "DemoSecurityGroup"
#define POLICY_URI "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR"

/* =========================================================================
 * 1. 基礎輔助函式
 * ========================================================================= */
static UA_ByteString loadLocalFile(const char *const path) {
    UA_ByteString fileContents = UA_STRING_NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return fileContents;
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
 * 2. ZTA SKS 存取控制 (嚴格白名單機制)
 * ========================================================================= */
// 當 Client 呼叫 GetSecurityKeys 時，這個回呼會驗證該 Client 是否有權限
static UA_Boolean
getUserExecutableOnObject_sks(UA_Server *server, UA_AccessControl *ac,
                              const UA_NodeId *sessionId, void *sessionContext,
                              const UA_NodeId *methodId, void *methodContext,
                              const UA_NodeId *objectId, void *objectContext) {
    if(sessionContext) {
        UA_ByteString *sessionUsername = (UA_ByteString *)sessionContext;
        UA_String motorClient = UA_STRING("MotorSubClient");
        UA_String sensorClient = UA_STRING("SensorClient");

        // 🛡️ 零信任防禦：只有指定的邊緣設備帳號，才允許索取群組金鑰
        if(UA_String_equal(sessionUsername, &motorClient) || UA_String_equal(sessionUsername, &sensorClient)) {
            return true;
        }
    }
    UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "⚠️ 拒絕未授權的設備存取 SKS 金鑰池！");
    return false;
}

// 建立 PubSub 金鑰群組
static void addSecurityGroup(UA_Server *server, UA_NodeId *outNodeId) {
    UA_SecurityGroupConfig config;
    memset(&config, 0, sizeof(UA_SecurityGroupConfig));
    config.keyLifeTime = DEMO_KEYLIFETIME_MINUTES * 60 * 1000; // 金鑰有效期限 (毫秒)
    config.securityPolicyUri = UA_STRING(POLICY_URI);
    config.securityGroupName = UA_STRING(DEMO_SECURITYGROUPNAME);
    config.maxFutureKeyCount = DEMO_MAXFUTUREKEYCOUNT;
    config.maxPastKeyCount = DEMO_MAXPASTKEYCOUNT;
    
    UA_Server_addSecurityGroup(server, UA_NS0ID(PUBLISHSUBSCRIBE_SECURITYGROUPS), &config, outNodeId);
}

/* =========================================================================
 * 主程式
 * ========================================================================= */
int main(int argc, char **argv) {
    if(argc < 3) {
        printf("用法: %s <sks-server-certificate.der> <sks-private-key.der>\n", argv[0]);
        return EXIT_FAILURE;
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    // 載入 SKS 伺服器自身的憑證與私鑰
    UA_ByteString certificate = loadLocalFile(argv[1]);
    UA_ByteString privateKey = loadLocalFile(argv[2]);
    if(certificate.length == 0 || privateKey.length == 0) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION, "無法載入 SKS 憑證或私鑰檔案！");
        return EXIT_FAILURE;
    }

    // 設定伺服器安全端點 (強制啟動 TLS 憑證加密驗證)
    UA_ServerConfig_setDefaultWithSecurityPolicies(config, 4841, &certificate, &privateKey, NULL, 0, NULL, 0, NULL, 0);

    // 🛡️ ZTA 防禦：自動裁撤不安全的 None 明文端點，強制所有連線必須簽章與加密
    for(size_t i = 0; i < config->endpointsSize; i++) {
        if(config->endpoints[i].securityMode == UA_MESSAGESECURITYMODE_NONE) {
            config->endpoints[i].securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        }
    }

    // 🛡️ ZTA 防禦：徹底關閉匿名登入，建立拉取金鑰專用的認證帳號
    static const UA_UsernamePasswordLogin defaultLogins[] = {
        {UA_STRING_STATIC("SensorClient"), UA_STRING_STATIC("ZtaTsnSecurePassword2026")},
        {UA_STRING_STATIC("MotorSubClient"), UA_STRING_STATIC("ZtaTsnSecurePassword2026")}
    };
    UA_String securityPolicyUri = config->securityPolicies[config->securityPoliciesSize-1].policyUri;
    config->accessControl.clear(&config->accessControl);
    UA_AccessControl_default(config, false, &securityPolicyUri, 2, defaultLogins);

    // 掛載 SKS 金鑰物件的存取白名單檢查
    config->accessControl.getUserExecutableOnObject = getUserExecutableOnObject_sks;

    // 啟動 PubSub 加密模組 (AES-256-CTR)
    config->pubSubConfig.securityPolicies = (UA_PubSubSecurityPolicy *)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
    config->pubSubConfig.securityPoliciesSize = 1;
    UA_PubSubSecurityPolicy_Aes256Ctr(config->pubSubConfig.securityPolicies, config->logging);

    // 註冊 Security Group (金鑰池)
    UA_NodeId outNodeId;
    addSecurityGroup(server, &outNodeId);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "🔒 專屬 SKS 金鑰伺服器啟動於 port 4841，等待設備拉取 PubSub 金鑰...");
    
    UA_Server_enableAllPubSubComponents(server);
    UA_Server_runUntilInterrupt(server);

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_Server_delete(server);
    return EXIT_SUCCESS;
}
