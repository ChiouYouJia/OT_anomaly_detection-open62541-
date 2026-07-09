#include <signal.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

UA_Boolean running = true;
static void stopHandler(int sig) { running = false; }

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server)); // 預設使用 4840 Port

    // 建立一個讓所有設備都能寫入的變數節點
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_String initVal = UA_STRING("System Initialized");
    UA_Variant_setScalar(&attr.value, &initVal, &UA_TYPES[UA_TYPES_STRING]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "CentralLog");
    // 開啟讀取與寫入權限，這讓 Client 能把 Log 寫進來
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "CentralLog"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, "CentralLog"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              attr, NULL, NULL);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🛠️ 日誌控制中心已啟動 (Port: 4840)，等待設備回傳 Log...");
    UA_Server_run(server, &running);
    UA_Server_delete(server);
    return 0;
}