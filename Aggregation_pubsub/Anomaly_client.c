#include <stdio.h>
#include <signal.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>

UA_Boolean running = true;
static void stopHandler(int sig) { running = false; }

static void logChangedHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                              UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    if(UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_STRING])) {
        UA_String logMsg = *(UA_String*)value->value.data;
        // 將這裡的輸出 Pipe 到您的 Drain3 或 BERT 模型中進行解析
        printf("🤖 [Anomaly Input] %.*s\n", (int)logMsg.length, logMsg.data);
    }
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    if(UA_Client_connect(client, "opc.tcp://localhost:4840") != UA_STATUSCODE_GOOD) {
        printf("❌ 無法連線至 Aggregation Server\n");
        UA_Client_delete(client);
        return 1;
    }

    printf("✅ 成功連線至聚合伺服器，準備將 Log 拋給 AIOps 模型...\n");

    UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(client, request, NULL, NULL, NULL);
    
    UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "CentralLog"));
    monRequest.requestedParameters.samplingInterval = 0.0; 
    monRequest.requestedParameters.queueSize = 1000;       
    
    UA_Client_MonitoredItems_createDataChange(client, response.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, monRequest, NULL, logChangedHandler, NULL);

    while(running) {
        UA_Client_run_iterate(client, 10);
    }

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}