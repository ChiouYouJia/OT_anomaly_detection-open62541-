#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>

UA_Boolean running = true;
UA_Server *server = NULL;
UA_NodeId aggDistanceNodeId;

static void stopHandler(int sig) { running = false; }

// 接收來自 Sensor 的資料，並寫入聚合伺服器
static void sensorDataChangeHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                                    UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    if(UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DOUBLE])) {
        UA_Double dist = *(UA_Double*)value->value.data;
        
        UA_Variant outVal;
        UA_Variant_setScalar(&outVal, &dist, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, aggDistanceNodeId, outVal);
    }
}

int main() {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    // ================= [1. 建立 Aggregation Server (Port 4840)] =================
    server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    UA_VariableAttributes logAttr = UA_VariableAttributes_default;
    UA_String initLog = UA_STRING("Aggregation Server Started");
    UA_Variant_setScalar(&logAttr.value, &initLog, &UA_TYPES[UA_TYPES_STRING]);
    logAttr.displayName = UA_LOCALIZEDTEXT("en-US", "CentralLog");
    logAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "CentralLog"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, "CentralLog"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              logAttr, NULL, NULL);

    UA_VariableAttributes distAttr = UA_VariableAttributes_default;
    UA_Double initDist = 0.0;
    UA_Variant_setScalar(&distAttr.value, &initDist, &UA_TYPES[UA_TYPES_DOUBLE]);
    distAttr.displayName = UA_LOCALIZEDTEXT("en-US", "AggregatedDistance");
    distAttr.accessLevel = UA_ACCESSLEVELMASK_READ;
    aggDistanceNodeId = UA_NODEID_STRING(1, "AggregatedDistance");
    UA_Server_addVariableNode(server, aggDistanceNodeId,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, "AggregatedDistance"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              distAttr, NULL, NULL);

    // 💡 關鍵修正 1：立刻啟動 Server 網路監聽！解除 Sensor 的等待死結
    UA_Server_run_startup(server);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🛠️ 聚合控制中心 (Aggregation Server) 已啟動 (Port: 4840)");

    // ================= [2. 建立 Internal Client 向 Sensor 抓資料] =================
    UA_Client *sensorClient = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(sensorClient));
    
    UA_Boolean sensorConnected = false;
    time_t last_try = 0; // 用於控制重試頻率

    // ================= [3. 主迴圈 (雙軌並行 + 斷線自動重連)] =================
    while(running) {
        // 處理作為 Server 接收到的讀寫/訂閱請求
        UA_Server_run_iterate(server, 10);
        
        // 💡 關鍵修正 2：非阻塞式的背景輪詢機制
        if (!sensorConnected) {
            // 每隔 3 秒嘗試連線一次，避免頻繁 Timeout 卡死 Server 迴圈
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                if(UA_Client_connect(sensorClient, "opc.tcp://localhost:4842") == UA_STATUSCODE_GOOD) {
                    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "✅ 成功連線到底層 Sensor，開始進行資料聚合");
                    
                    UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
                    UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(sensorClient, request, NULL, NULL, NULL);
                    
                    UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "DistanceValue"));
                    UA_Client_MonitoredItems_createDataChange(sensorClient, response.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, monRequest, NULL, sensorDataChangeHandler, NULL);
                    
                    sensorConnected = true;
                }
            }
        } else {
            // 處理 Client 向下訂閱 Sensor 產生的事件
            UA_Client_run_iterate(sensorClient, 10);
            
            // 💡 關鍵修正 3：如果 Sensor 突然當機或關閉，切換回重連模式
            UA_SecureChannelState channelState;
            UA_SessionState sessionState;
            UA_StatusCode connectStatus;
            UA_Client_getState(sensorClient, &channelState, &sessionState, &connectStatus);

            // 當底層的 SecureChannel 處於關閉狀態，代表連線已經斷開
            if (channelState == UA_SECURECHANNELSTATE_CLOSED) {
                UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "⚠️ Sensor 連線中斷，切換為背景重連模式...");
                sensorConnected = false;
            }
        }
    }

    UA_Server_run_shutdown(server);

    UA_Client_disconnect(sensorClient);
    UA_Client_delete(sensorClient);
    UA_Server_delete(server);
    return 0;
}