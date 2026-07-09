#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sqlite3.h>

#include "common.h" // 確保你有引入官方的 common.h 來使用 loadFile 函式

sqlite3 *db;
static UA_Boolean running = true;

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION, "接收到中斷訊號，準備關閉伺服器...");
    running = false;
}

// -------------------------------------------------------------
// SQLite 查詢回呼函式
// -------------------------------------------------------------
static int check_revoked_callback(void *data, int argc, char **argv, char **azColName) {
    bool *is_revoked = (bool*)data;
    if (argc > 0 && argv[0] != NULL) {
        if (strcmp(argv[0], "REVOKED") == 0) *is_revoked = true;
    }
    return 0;
}

// -------------------------------------------------------------
// 🌟 核心：覆寫官方 StartSigningRequest 加入 ZTA 邏輯
// -------------------------------------------------------------
static UA_StatusCode
official_StartSigningRequest_ZTA(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionHandle,
                                 const UA_NodeId *methodId, void *methodContext,
                                 const UA_NodeId *objectId, void *objectContext,
                                 size_t inputSize, const UA_Variant *input,
                                 size_t outputSize, UA_Variant *output) {

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "📩 收到標準 GDS StartSigningRequest 請求...");

    if(inputSize < 5) return UA_STATUSCODE_BADARGUMENTSMISSING;

    UA_String *subjectName = (UA_String*)input[2].data;
    UA_String *subjectAltName = (UA_String*)input[3].data;
    UA_ByteString *csrData = (UA_ByteString*)input[4].data;

    // 解析設備序號
    char subject_buf[256] = {0};
    memcpy(subject_buf, subjectName->data, subjectName->length);
    char serial_buf[64] = {0};
    char *serial_ptr = strstr(subject_buf, "SERIALNUMBER=");
    if(serial_ptr) {
        sscanf(serial_ptr, "SERIALNUMBER=%63[^,]", serial_buf);
    } else {
        strcpy(serial_buf, "UNKNOWN_SERIAL");
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "📋 [ZTA 審查] 解析出設備序號: %s", serial_buf);

    // SQLite 黑名單檢查
    bool is_revoked = false;
    char *check_sql = sqlite3_mprintf("SELECT status FROM issued_certificates WHERE serial_number=%Q;", serial_buf);
    sqlite3_exec(db, check_sql, check_revoked_callback, &is_revoked, NULL);
    sqlite3_free(check_sql);

    if (is_revoked) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "❌ [ZTA 安全阻擋] 設備 %s 在黑名單中！", serial_buf);
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    }

    // 呼叫官方 API 進行簽發
    UA_ByteString caCert = loadFile("ca_cert.der"); // 你的發證 CA 憑證
    UA_ByteString caKey = loadFile("ca_key.der");   // 你的發證 CA 私鑰
    UA_ByteString signedCert = UA_BYTESTRING_NULL;
    UA_ByteString outPrivateKey = UA_BYTESTRING_NULL; // 接收生成的私鑰

    UA_StatusCode res = UA_CreateCertificate(UA_Log_Stdout, 
                                             subjectName, 1, 
                                             subjectAltName, 1, 
                                             UA_CERTIFICATEFORMAT_DER, 
                                             NULL, 
                                             &outPrivateKey, 
                                             &signedCert);

    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "❌ 官方 API 憑證簽發失敗！");
        return res;
    }

    // 釋放不需要的私鑰空間，保留 signedCert 回傳
    UA_ByteString_clear(&outPrivateKey);
    // 更新 SQLite 紀錄
    char *insert_sql = sqlite3_mprintf(
        "INSERT INTO issued_certificates (serial_number, status, issue_date) "
        "VALUES (%Q, 'ACTIVE', datetime('now')) "
        "ON CONFLICT(serial_number) DO UPDATE SET status='ACTIVE', issue_date=datetime('now');",
        serial_buf);
    sqlite3_exec(db, insert_sql, NULL, NULL, NULL);
    sqlite3_free(insert_sql);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "💾 [DB 紀錄] 設備 %s 狀態已同步，憑證簽發成功。", serial_buf);

    // 如果你的系統目前簡化處理，直接在此返回簽好的憑證給 Client
    // UA_Variant_setScalarCopy(&output[0], &signedCert, &UA_TYPES[UA_TYPES_BYTESTRING]);

    UA_ByteString_clear(&signedCert);
    UA_ByteString_clear(&caCert);
    UA_ByteString_clear(&caKey);

    return UA_STATUSCODE_GOOD;
}

// -------------------------------------------------------------
// 🌟 融合版 main 函式
// -------------------------------------------------------------
int main(int argc, char* argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    if (sqlite3_open("sks_management.db", &db) != SQLITE_OK) {
        fprintf(stderr, "❌ 無法開啟資料庫！\n");
        return EXIT_FAILURE;
    }

    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    UA_String storePath = UA_STRING_NULL;

    // 讀取啟動參數
    if(argc >= 3) {
        certificate = loadFile(argv[1]);
        privateKey = loadFile(argv[2]);
    } else {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                     "缺少啟動參數。請使用: ./gds_server <server-certificate.der> <private-key.der> [<pki-folder-path>]");
        return EXIT_FAILURE;
    }

    if(argc >= 4) {
        storePath = UA_STRING(argv[3]);
    } else {
        char storePathDir[4096];
        if(!getcwd(storePathDir, sizeof(storePathDir))) return EXIT_FAILURE;
        storePath = UA_STRING(storePathDir);
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    // 🌟 關鍵升級：使用 Filestore 進行安全配置初始化
    UA_StatusCode retval = UA_ServerConfig_setDefaultWithFilestore(config, 4840, &certificate, &privateKey, storePath);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION, "❌ Filestore 初始化失敗，請檢查 PKI 資料夾結構！");
        goto cleanup;
    }
    // 🌟 將官方 GDS 方法替換為我們的 ZTA 審查邏輯
    UA_NodeId startSigningNodeId = UA_NODEID_NUMERIC(0, 11956);
    UA_Server_setMethodNode_callback(server, startSigningNodeId, official_StartSigningRequest_ZTA);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "🔒 GDS Server (ZTA + Filestore) 已成功啟動！");
    
    if(running) {
        retval = UA_Server_run(server, &running);
    }

cleanup:
    UA_Server_delete(server);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    sqlite3_close(db);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
