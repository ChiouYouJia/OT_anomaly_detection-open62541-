#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>

UA_Boolean running = true;
static void stopHandler(int sig) { running = false; }

static void logChangedHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                              UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    if(UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_STRING])) {
        UA_String logMsg = *(UA_String*)value->value.data;
        printf("🤖 [Anomaly Input] %.*s\n", (int)logMsg.length, logMsg.data);
    }
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    UA_Boolean connected = false;
    time_t last_try = 0;
    printf("⏳ 等待聚合伺服器 (Aggregation Server) 上線...\n");

    while(running) {
        if (!connected) {
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                
                // 💡 乾淨的 127.0.0.1，沒有殘留的 timeout 猛藥
                if(UA_Client_connect(client, "opc.tcp://127.0.0.1:4840") == UA_STATUSCODE_GOOD) {
                    connected = true;
                    printf("✅ 成功連線至聚合伺服器，準備將 Log 拋給 AIOps 模型...\n");

                    UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
                    UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(client, request, NULL, NULL, NULL);
                    
                    UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "CentralLog"));
                    monRequest.requestedParameters.samplingInterval = 0.0; 
                    monRequest.requestedParameters.queueSize = 1000;       
                    
                    UA_Client_MonitoredItems_createDataChange(client, response.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, monRequest, NULL, logChangedHandler, NULL);
                } else {
                    UA_Client_disconnect(client);
                }
            }
        } else {
            UA_Client_run_iterate(client, 0);

            UA_SecureChannelState channelState;
            UA_SessionState sessionState;
            UA_StatusCode connectStatus;
            UA_Client_getState(client, &channelState, &sessionState, &connectStatus);

            // 💡 強化斷線防線
            if (channelState != UA_SECURECHANNELSTATE_OPEN) {
                connected = false;
                printf("⚠️ 聚合伺服器連線中斷，背景重連中...\n");
                UA_Client_disconnect(client);
            }
        }
        
        // 💡 終極效能鎖：休眠 10 毫秒
        usleep(10000); 
    }

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}