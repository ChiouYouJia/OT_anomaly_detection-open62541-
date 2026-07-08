#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/server_pubsub.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

static volatile UA_Boolean running = true;
static void stopHandler(int sig) { running = false; }

#define DEMO_SECURITYGROUPNAME "DemoSecurityGroup"
#define POLICY_URI "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR"

static UA_ByteString loadLocalFile(const char *const path) {
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

// 允許 Sensor 與 Client 拉取金鑰的權限檢查
static UA_Boolean getUserExecutableOnObject_sks(UA_Server *server, UA_AccessControl *ac,
                                                const UA_NodeId *sessionId, void *sessionContext, 
                                                const UA_NodeId *methodId, void *methodContext, 
                                                const UA_NodeId *objectId, void *objectContext) {
    
    return true; 
}

// ✅ 呼叫真正的 SKS API 來建立安全群組
static UA_StatusCode addSecurityGroup(UA_Server *server, UA_NodeId *outNodeId) {
    UA_SecurityGroupConfig config;
    memset(&config, 0, sizeof(UA_SecurityGroupConfig));
    config.securityGroupName = UA_STRING(DEMO_SECURITYGROUPNAME);
    config.securityPolicyUri = UA_STRING(POLICY_URI);
    config.keyLifeTime = 10 * 1000; // 10 秒鐘換一次金鑰
    config.maxFutureKeyCount = 1;
    config.maxPastKeyCount = 1;
    
    // 依賴 Full Namespace Zero 才能找到這個父節點
    UA_NodeId securityGroupParent = UA_NS0ID(PUBLISHSUBSCRIBE_SECURITYGROUPS);
    return UA_Server_addSecurityGroup(server, securityGroupParent, &config, outNodeId);
}

int main(int argc, char **argv) {
    if(argc < 3) {
        printf("用法: %s <sks-cert.der> <sks-key.der>\n", argv[0]);
        return EXIT_FAILURE;
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    UA_ByteString certificate = loadLocalFile(argv[1]);
    UA_ByteString privateKey = loadLocalFile(argv[2]);

    UA_ServerConfig_setDefaultWithSecurityPolicies(config, 4841, 
                                                   &certificate, &privateKey, 
                                                   NULL, 0, NULL, 0, NULL, 0);

    static const UA_UsernamePasswordLogin defaultLogins[] = {
        {UA_STRING_STATIC("SensorClient"), UA_STRING_STATIC("ZtaTsnSecurePassword2026")},
        {UA_STRING_STATIC("MotorSubClient"), UA_STRING_STATIC("ZtaTsnSecurePassword2026")}
    };

    config->accessControl.clear(&config->accessControl);
    UA_ByteString *policyUri = &config->securityPolicies[config->securityPoliciesSize-1].policyUri;
    UA_AccessControl_default(config, false, NULL, sizeof(defaultLogins)/sizeof(defaultLogins[0]), defaultLogins);
    config->accessControl.getUserExecutableOnObject = getUserExecutableOnObject_sks;

    config->pubSubConfig.securityPolicies = (UA_PubSubSecurityPolicy *)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
    config->pubSubConfig.securityPoliciesSize = 1;
    UA_PubSubSecurityPolicy_Aes256Ctr(config->pubSubConfig.securityPolicies, config->logging);

    UA_Server_enableAllPubSubComponents(server);

    // ✅ 2. 新增安全群組，並檢查是否真的成功
    UA_NodeId outNodeId;
    UA_StatusCode retval = addSecurityGroup(server, &outNodeId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "❌ SKS 安全群組建立失敗: %s", UA_StatusCode_name(retval));
        return EXIT_FAILURE;
    } else {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "✅ SKS 安全群組建立成功！等待派發金鑰...");
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "🔒 真・SKS 金鑰伺服器啟動於 port 4841，等待動態派發金鑰...");

    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);
    UA_Server_run(server, &running);

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_Server_delete(server);
    return EXIT_SUCCESS;
}