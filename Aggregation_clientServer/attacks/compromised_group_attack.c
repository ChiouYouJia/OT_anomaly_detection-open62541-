// =============================================================================
// 進階攻擊：被入侵的合法節點・跨群版（compromised_group）
// =============================================================================
// 為什麼需要這個「加強版」（見 net/TOPO_SCALEUP_DESIGN.md）：
//   compromised_node_attack 回報的是「sensor 真值 ± 20」，這在單 sensor 拓撲下
//   可以被**一個純量平特徵**抓到：
//       report_dev_max = max_i | report_i − 最近的 sensor 樣本 |
//   實測 RF 拿到這個特徵就 PR-AUC 1.00，與 GNN 打平 —— 於是「圖結構有沒有加值」
//   永遠問不出來，因為破綻本來就只需要一個純量。
//
//   本版把破綻升級成**只有拓撲才看得到**的形式：
//     攻擊者冒用 motor k 的身分，但回報的值是**另一台 sensor 當下的真實值**。
//     · 對「全域最小偏差」而言：這個值等於某台 sensor 的真值 → 偏差 = 0
//       → **report_dev_max / report_spread 這類全域平特徵完全失效**
//     · 對「我這一群」而言：motor k 訂閱的是 sensor A，卻報了 sensor B 的值
//       → 與**同群 peer**（同樣訂閱 A 的那些 motor）明顯不一致
//   要看出後者，必須知道「誰跟誰同群」——那是**訂閱邊的結構**，
//   只有走圖的模型拿得到。這就是項目 2 想證明的差距。
//
//   ⚠️ 各 sensor 的值域刻意相同（見 sensor_pub.c 註解），所以也**不能**用
//     「值落在哪個區間」這種平特徵反推群別。
//
// ground truth：被竄改的回報在訊息尾端埋 " #MAL" 記號（僅供評估，偵測器看不到）。
//
// ⚠️ 兩個行程的設計（2026-08-09 修）：
//   第一版讓同一個行程同時訂閱 own + foreign 兩台 sensor，結果**自己製造了指紋**：
//     · 這個節點在圖上有 2 條訂閱邊，真 motor 只有 1 條 → 不用看值就能抓到它
//     · build_graph 的「這台 motor 屬於哪一群」也被歸錯（實測 report_dev_own 反轉：
//       正常秒 33.96、惡意秒 0.04）
//   修法：拆成兩個行程、兩個**不同的來源身分**
//     · reader  ：綁另一個來源 IP，訂閱 foreign sensor，把最新值寫進暫存檔
//                 （模擬攻擊者在別處已有的立足點）
//     · 主行程  ：只訂閱 own sensor（與真 motor 完全同構，1 條訂閱邊），
//                 竄改時從暫存檔讀 foreign 值
//   這樣攻擊者在網路層與真 motor **逐邊同構**，破綻只剩「值與同群 peer 不一致」。
//
// 用法：
//   ./compromised_group_attack --reader <foreign_sensor_id> <value_file>
//   ./compromised_group_attack <session_name> <own_sensor_id> <foreign_sensor_id> <value_file>
//   預設： MotorSource2 1 2 /tmp/cg_foreign.val
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
#define N_TAMPER        20
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

static char   g_session[64] = "MotorSource2";
static int    g_own_sensor = 1, g_foreign_sensor = 2;
static double g_foreign_val = -1.0;    // 另一群 sensor 的最新真值（偷來當幌子）

static char   g_valfile[256] = "/tmp/cg_foreign.val";
static UA_Client *g_logCli = NULL;
static time_t     g_start  = 0;
static int       *g_is_tamper = NULL;
static int        g_baseline = 0;
static int        g_last_reported = -1;
static int        g_n_tamper = 0, g_n_skipped = 0;

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

// reader 行程：訂閱別群 sensor，把最新值寫進暫存檔（不寫任何 log、不碰 agg_server）
static void onForeign(UA_Client *c, UA_UInt32 subId, void *subCtx,
                      UA_UInt32 monId, void *monCtx, UA_DataValue *v) {
    (void)c; (void)subId; (void)subCtx; (void)monId; (void)monCtx;
    if (!(v->hasValue && UA_Variant_hasScalarType(&v->value, &UA_TYPES[UA_TYPES_DOUBLE])))
        return;
    g_foreign_val = *(UA_Double *)v->value.data;
    char tmp[300];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_valfile);
    FILE *f = fopen(tmp, "w");
    if (f) {
        fprintf(f, "%.17g\n", g_foreign_val);
        fclose(f);
        rename(tmp, g_valfile);        // 原子替換，主行程不會讀到半截
    }
}

// 主行程：從暫存檔讀 reader 抓到的別群真值
static double read_foreign(void) {
    FILE *f = fopen(g_valfile, "r");
    if (!f) return -1.0;
    double v = -1.0;
    if (fscanf(f, "%lf", &v) != 1) v = -1.0;
    fclose(f);
    return v;
}

// 自己這群 sensor 的通知：與真 motor 完全同步地回報（正常秒逐值相同）
static void onOwn(UA_Client *c, UA_UInt32 subId, void *subCtx,
                  UA_UInt32 monId, void *monCtx, UA_DataValue *v) {
    (void)c; (void)subId; (void)subCtx; (void)monId; (void)monCtx;
    if (!(v->hasValue && UA_Variant_hasScalarType(&v->value, &UA_TYPES[UA_TYPES_DOUBLE])))
        return;
    double own = *(UA_Double *)v->value.data;

    int el = (int)(time(NULL) - g_start);
    if (el < 0 || el >= g_baseline) return;
    if (el == g_last_reported) return;
    g_last_reported = el;

    char line[1024], msg[256];
    if (g_is_tamper[el]) {
        g_foreign_val = read_foreign();
        if (g_foreign_val < 0) {
            // 還沒收到別群的值 → 這一秒放棄竄改（寧可少一筆，也不要報一個
            // 憑空捏造的值：那會退化成舊版攻擊，又被平特徵抓到）。
            g_n_skipped++;
            snprintf(msg, sizeof(msg), "[Motor] Received distance: %.1f cm%s", own, BEN_MARK);
        } else {
            snprintf(msg, sizeof(msg), "[Motor] Received distance: %.1f cm%s",
                     g_foreign_val, MAL_MARK);
            g_n_tamper++;
            printf("[COMPROMISED-GROUP] t=%ds TAMPER: own(sensor%d)=%.3g "
                   "reported=foreign(sensor%d)=%.3g\n",
                   el, g_own_sensor, own, g_foreign_sensor, g_foreign_val);
        }
    } else {
        snprintf(msg, sizeof(msg), "[Motor] Received distance: %.1f cm%s", own, BEN_MARK);
    }
    build_log(line, sizeof(line), msg);
    if (g_logCli) write_log(g_logCli, line);
}

static UA_Client *connect_sensor(int sensor_id, const char *tag) {
    char url[64];
    snprintf(url, sizeof(url), "opc.tcp://127.0.0.1:%d", 4841 + sensor_id);
    UA_Client *c = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(c));
    if (UA_Client_connect(c, url) != UA_STATUSCODE_GOOD) {
        printf("[COMPROMISED-GROUP] %s connect failed (%s)\n", tag, url);
        UA_Client_delete(c);
        return NULL;
    }
    return c;
}

static void subscribe_distance(UA_Client *c, UA_Client_DataChangeNotificationCallback cb) {
    UA_CreateSubscriptionRequest sr = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse srr =
        UA_Client_Subscriptions_create(c, sr, NULL, NULL, NULL);
    UA_MonitoredItemCreateRequest mi =
        UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(1, "DistanceValue"));
    UA_Client_MonitoredItems_createDataChange(
        c, srr.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, mi, NULL, cb, NULL);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, stopHandler); signal(SIGTERM, stopHandler);
    // ---- reader 模式：只負責偷看別群 sensor 並寫檔（獨立身分、獨立來源 IP）----
    if (argc > 1 && strcmp(argv[1], "--reader") == 0) {
        if (argc > 2) g_foreign_sensor = atoi(argv[2]);
        if (argc > 3) snprintf(g_valfile, sizeof(g_valfile), "%s", argv[3]);
        UA_Client *fc = connect_sensor(g_foreign_sensor, "foreign sensor(reader)");
        if (!fc) return 1;
        subscribe_distance(fc, onForeign);
        printf("[CG-READER] watching sensor%d → %s\n", g_foreign_sensor, g_valfile);
        time_t st = time(NULL);
        while (running && (int)(time(NULL) - st) < BASELINE_SEC + 30)
            UA_Client_run_iterate(fc, 50);
        UA_Client_disconnect(fc); UA_Client_delete(fc);
        return 0;
    }

    if (argc > 1) snprintf(g_session, sizeof(g_session), "%s", argv[1]);
    if (argc > 2) g_own_sensor = atoi(argv[2]);
    if (argc > 3) g_foreign_sensor = atoi(argv[3]);
    if (argc > 4) snprintf(g_valfile, sizeof(g_valfile), "%s", argv[4]);
    if (g_own_sensor < 1 || g_foreign_sensor < 1 || g_own_sensor == g_foreign_sensor) {
        fprintf(stderr, "用法: %s <session> <own_sensor_id> <foreign_sensor_id>"
                        "（兩個 id 必須不同）\n", argv[0]);
        return 1;
    }

    // 主行程**只**連自己那台 sensor —— 與真 motor 逐邊同構（1 條訂閱邊）
    UA_Client *ownCli = connect_sensor(g_own_sensor, "own sensor");
    if (!ownCli) return 1;

    UA_Client *logCli = UA_Client_new();
    UA_ClientConfig *lc = UA_Client_getConfig(logCli);
    UA_ClientConfig_setDefault(lc);
    UA_String_clear(&lc->sessionName);
    lc->sessionName = UA_STRING_ALLOC(g_session);        // ← 冒用合法身分
    if (UA_Client_connect(logCli, "opc.tcp://127.0.0.1:4840") != UA_STATUSCODE_GOOD) {
        printf("[COMPROMISED-GROUP] agg connect failed\n"); return 1;
    }

    printf("[COMPROMISED-GROUP] Impersonating '%s'; own=sensor%d foreign=sensor%d (via %s)\n",
           g_session, g_own_sensor, g_foreign_sensor, g_valfile);
    subscribe_distance(ownCli, onOwn);

    srand((unsigned)time(NULL) ^ 0xC0FFEE);
    static int is_tamper[BASELINE_SEC]; memset(is_tamper, 0, sizeof(is_tamper));
    for (int i = 0; i < N_TAMPER; i++) is_tamper[rand() % BASELINE_SEC] = 1;

    g_logCli = logCli; g_start = time(NULL);
    g_is_tamper = is_tamper; g_baseline = BASELINE_SEC;

    while (running) {
        if ((int)(time(NULL) - g_start) >= BASELINE_SEC) break;
        UA_Client_run_iterate(ownCli, 50);       // 自己的通知 → 觸發回報
    }

    printf("[COMPROMISED-GROUP] Done (%d tampered, %d skipped for lack of foreign value).\n",
           g_n_tamper, g_n_skipped);
    UA_Client_disconnect(ownCli); UA_Client_delete(ownCli);
    UA_Client_disconnect(logCli); UA_Client_delete(logCli);
    return 0;
}
