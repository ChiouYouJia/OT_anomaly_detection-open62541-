#include <stdio.h>
#include <signal.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/plugin/log_stdout.h>

UA_Boolean running = true;
static void stopHandler(int sig) { running = false; }

// 當伺服器上的 CentralLog 變數被更新時，觸發此 Callback
static void logChangedHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                              UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    if(UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_STRING])) {
        UA_String logMsg = *(UA_String*)value->value.data;
        // 印出最新的 Log，你可以把這個標準輸出 Pipe 給其他程序
        printf("📝 [中央日誌] %.*s\n", (int)logMsg.length, logMsg.data);
    }
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    if(UA_Client_connect(client, "opc.tcp://localhost:4840") != UA_STATUSCODE_GOOD) {
        printf("❌ 無法連線至日誌控制中心\n");
        UA_Client_delete(client);
        return 1;
    }

    printf("✅ 成功連線至控制中心，開始監聽系統日誌...\n");

    // 建立訂閱機制 (Subscription)
    UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(client, request, NULL, NULL, NULL);
    UA_UInt32 subId = response.subscriptionId;

    // 訂閱名為 CentralLog 的節點
    UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "CentralLog"));
    monRequest.requestedParameters.samplingInterval = 0.0; // 0.0 代表只要一有變動立刻送出，不等待！
    monRequest.requestedParameters.queueSize = 1000;       // 把暫存佇列加大到 1000 筆
    monRequest.requestedParameters.discardOldest = false;  // 確保舊 Log 絕對不會被丟棄
    
    UA_Client_MonitoredItems_createDataChange(client, subId, UA_TIMESTAMPSTORETURN_BOTH, monRequest, NULL, logChangedHandler, NULL);

    // 保持 Client 運作，持續接收事件
    while(running) {
        UA_Client_run_iterate(client, 100);
    }

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}