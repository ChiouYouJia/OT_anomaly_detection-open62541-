#include "client_bootstrap.h"
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// 🌟 引入 OpenSSL C API 標頭檔
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

static UA_ByteString loadLocalFile(const char *const path) {
    UA_ByteString fileContents = UA_STRING_NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return fileContents;
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t)ftell(fp);
    fileContents.data = (UA_Byte *)malloc(fileContents.length);
    if (fileContents.data) {
        fseek(fp, 0, SEEK_SET);
        fread(fileContents.data, 1, fileContents.length, fp);
    }
    fclose(fp);
    return fileContents;
}

UA_Boolean perform_sks_bootstrap(const char* sks_url,
                                 const char* group_id,
                                 const char* serial_number,
                                 const char* output_path) {

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "===> [標準 GDS 模式] 啟動符合國際規範之憑證簽發流程...");

    UA_Boolean success = false;
    UA_ByteString csrByteString = UA_BYTESTRING_NULL;

    // -------------------------------------------------------------
    // 步驟 0: 在記憶體中生成 RSA 私鑰與 CSR 請求 (零外部依賴)
    // -------------------------------------------------------------
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔑 正在記憶體中生成 2048-bit RSA 私鑰...");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    if (!pkey) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ RSA 私鑰生成失敗！");
        return false;
    }

    // 將私鑰寫入本地檔案 (因為後續 Publisher 加密通訊需要用到這把專屬私鑰)
    FILE *key_fp = fopen("client_key.der", "wb");
    if (key_fp) {
        i2d_PrivateKey_fp(key_fp, pkey);
        fclose(key_fp);
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "📜 正在建立憑證簽章請求 (CSR)...");

    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, pkey);

    // 🌟 設定 CSR 的 Subject 屬性 (格式必須配合 Server 端的解析)
    X509_NAME *name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"EdgeDevice", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)group_id, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "serialNumber", MBSTRING_ASC, (const unsigned char*)serial_number, -1, -1, 0);

    // 使用私鑰對 CSR 進行簽章 (SHA-256)
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ CSR 簽章失敗！");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return false;
    }

    // 將 CSR 轉為二進位 (DER) 格式並存入 UA_ByteString
    int csr_len = i2d_X509_REQ(req, NULL);
    UA_ByteString_allocBuffer(&csrByteString, csr_len);
    unsigned char *p = csrByteString.data;
    i2d_X509_REQ(req, &p);

    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    // -------------------------------------------------------------
    // 步驟 1: 配置 OPC UA Client 加密連線 (掛載出廠憑證建立安全通道)
    // -------------------------------------------------------------
    UA_Client *client = UA_Client_new();
    UA_ClientConfig *config = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(config);

    // 🌟 核心升級：讀取「出廠憑證」與「出廠私鑰」，直接用於連線身分驗證
    UA_ByteString initialCert = loadLocalFile("initial_client_cert.der");
    UA_ByteString initialKey = loadLocalFile("initial_client_key.der");
    
    if (initialCert.length > 0 && initialKey.length > 0) {
        config->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        UA_ClientConfig_setDefaultEncryption(config, initialCert, initialKey, NULL, 0, NULL, 0);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🛡️ 已掛載出廠憑證，準備建立安全通道...");
    } else {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "⚠️ 未找到出廠憑證/私鑰，將嘗試非加密連線 (可能遭 Server 拒絕)");
    }

    UA_StatusCode retval = UA_Client_connect(client, sks_url);
    if (retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ 連線至 SKS 伺服器失敗！錯誤碼: %s", UA_StatusCode_name(retval));
        goto cleanup;
    }

    // -------------------------------------------------------------
    // 步驟 2: 呼叫標準 StartSigningRequest (提交 CSR)
    // -------------------------------------------------------------
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "[GDS Step 1] 正在提交憑證簽發請求 (StartSigningRequest)...");

    UA_Variant inputStart[5];
    for(int i=0; i<5; i++) UA_Variant_init(&inputStart[i]);

    UA_NodeId groupIdNode = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_Variant_setScalar(&inputStart[0], &groupIdNode, &UA_TYPES[UA_TYPES_NODEID]);

    UA_NodeId typeIdNode = UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_Variant_setScalar(&inputStart[1], &typeIdNode, &UA_TYPES[UA_TYPES_NODEID]);

    char subject_buf[256];
    snprintf(subject_buf, sizeof(subject_buf), "CN=EdgeDevice, O=%s, SERIALNUMBER=%s", group_id, serial_number);
    UA_String subjectStr = UA_STRING(subject_buf);
    UA_Variant_setScalar(&inputStart[2], &subjectStr, &UA_TYPES[UA_TYPES_STRING]);

    UA_String subjectAltStr = UA_STRING("URI:urn:open62541.unconfigured.application");
    UA_Variant_setScalar(&inputStart[3], &subjectAltStr, &UA_TYPES[UA_TYPES_STRING]);

    UA_Variant_setScalar(&inputStart[4], &csrByteString, &UA_TYPES[UA_TYPES_BYTESTRING]);

    size_t outputStartSize = 0;
    UA_Variant *outputStart = NULL;
    
    retval = UA_Client_call(client,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
                            UA_NODEID_NUMERIC(0, 3804),
                            5, inputStart,
                            &outputStartSize, &outputStart);

    if (retval != UA_STATUSCODE_GOOD || outputStartSize != 1) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ StartSigningRequest 失敗或遭拒絕！錯誤碼: %s", UA_StatusCode_name(retval));
        goto cleanup;
    }

    UA_NodeId *asyncOperationId = (UA_NodeId *)outputStart[0].data;
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "[GDS Step 2] 審查通過！取得任務 ID，準備領取憑證 (FinishSigningRequest)...");

    // -------------------------------------------------------------
    // 步驟 3: 呼叫標準 FinishSigningRequest (領取憑證)
    // -------------------------------------------------------------
    UA_Variant inputFinish[1];
    UA_Variant_init(&inputFinish[0]);
    UA_Variant_setScalarCopy(&inputFinish[0], asyncOperationId, &UA_TYPES[UA_TYPES_NODEID]);

    size_t outputFinishSize = 0;
    UA_Variant *outputFinish = NULL;

    retval = UA_Client_call(client,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP),
                            UA_NODEID_NUMERIC(0, 3806),
                            1, inputFinish,
                            &outputFinishSize, &outputFinish);

    UA_Variant_clear(&inputFinish[0]);

    // -------------------------------------------------------------
    // 步驟 4: 儲存正式營運憑證
    // -------------------------------------------------------------
    if (retval == UA_STATUSCODE_GOOD && outputFinishSize >= 1) {
        if (UA_Variant_hasScalarType(&outputFinish[0], &UA_TYPES[UA_TYPES_BYTESTRING])) {
            UA_ByteString *receivedCert = (UA_ByteString *)outputFinish[0].data;
            FILE *fp = fopen(output_path, "wb");
            if (fp) {
                size_t written = fwrite(receivedCert->data, 1, receivedCert->length, fp);
                fclose(fp);
                if (written == receivedCert->length) {
                    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "✅ [ZTA] 正式營運憑證已成功取得並儲存至: %s", output_path);
                    success = true;
                }
            }
        }
    } else {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ 領取憑證失敗！錯誤碼: %s", UA_StatusCode_name(retval));
    }

cleanup:
    // 清理資源
    UA_ByteString_clear(&csrByteString);
    UA_ByteString_clear(&initialCert);
    UA_ByteString_clear(&initialKey);
    
    if (outputStart) UA_Array_delete(outputStart, outputStartSize, &UA_TYPES[UA_TYPES_VARIANT]);
    if (outputFinish) UA_Array_delete(outputFinish, outputFinishSize, &UA_TYPES[UA_TYPES_VARIANT]);
    
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return success;
}
