#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>

UA_Boolean running = true;
static void stopHandler(int sig) { running = false; }

// CentralLog 現在是 String 陣列（server 端 ring buffer），每行前綴 "#<seq> "。
// 用 seq 去重：只處理序號比上次大的行。一連上會先收到整包 buffer（補歷史），
// 之後每次通知拿到最新快照，掃過去挑出沒看過的新行即可 —— 不漏接、不重複。
// 註：last_seq 跨重連保持單調；若「聚合伺服器本身」重啟（seq 歸零），請一併重啟本程式。
static uint64_t last_seq = 0;

static void logChangedHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                              UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    if(!UA_Variant_hasArrayType(&value->value, &UA_TYPES[UA_TYPES_STRING]))
        return;
    UA_String *lines = (UA_String *)value->value.data;
    size_t n = value->value.arrayLength;
    for (size_t i = 0; i < n; i++) {
        UA_String s = lines[i];
        // 解析前綴 "#<seq> "
        if (s.length < 2 || s.data[0] != '#') continue;
        uint64_t seq = 0; size_t p = 1;
        while (p < s.length && s.data[p] >= '0' && s.data[p] <= '9')
            seq = seq * 10 + (uint64_t)(s.data[p++] - '0');
        if (seq <= last_seq) continue;   // 舊行，去重跳過
        last_seq = seq;

        size_t off = (p < s.length && s.data[p] == ' ') ? p + 1 : p;  // 跳過序號後的空白
        int         msg_len = (int)(s.length - off);
        const char *msg_ptr = (const char *)(s.data + off);
        printf("[Anomaly Input] %.*s\n", msg_len, msg_ptr);
        // 👉 你的異常偵測邏輯掛這裡：純 log 文字 = msg_ptr（長度 msg_len），序號 = seq
    }
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    UA_Boolean connected = false;
    time_t last_try = 0;
    printf("Waiting for Aggregation Server to come online...\n");

    while(running) {
        if (!connected) {
            if (time(NULL) - last_try >= 3) {
                last_try = time(NULL);
                
                // 💡 乾淨的 127.0.0.1，沒有殘留的 timeout 猛藥
                if(UA_Client_connect(client, "opc.tcp://127.0.0.1:4840") == UA_STATUSCODE_GOOD) {
                    connected = true;
                    printf("Connected to Aggregation Server; forwarding logs to the AIOps model...\n");

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
                printf("Aggregation Server connection lost; reconnecting in background...\n");
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