#include "client_bootstrap.h"
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 輔助函式：讀取本地檔案
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

    // -------------------------------------------------------------
    // 步驟 0: 本地生成私鑰與 CSR 請求 (維持你的系統呼叫寫法)
    // -------------------------------------------------------------
    UA_ByteString csrByteString = UA_BYTESTRING_NULL;
    EVP_PKEY *pkey = NULL;
    X509_REQ *req = NULL;

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🔑 正在記憶體中生成 2048-bit RSA 私鑰...");

    // 1. 產生 RSA 2048 私鑰
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    if (!pkey) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ RSA 私鑰生成失敗！");
        return false;
    }

    // 2. 將私鑰寫入本地檔案 (因為後續加密通訊或下次重啟還需要用到這把專屬私鑰)
    FILE *key_fp = fopen("client_key.der", "wb");
    if (key_fp) {
        i2d_PrivateKey_fp(key_fp, pkey); // 直接以 DER 格式寫入檔案
        fclose(key_fp);
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "📜 正在建立憑證簽章請求 (CSR)...");

    // 3. 建立 CSR
    req = X509_REQ_new();
    X509_REQ_set_version(req, 0); // CSR version 1
    X509_REQ_set_pubkey(req, pkey);

    // 4. 設定 CSR 的 Subject 屬性 (對齊 Server 端的解析邏輯)
    X509_NAME *name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"EdgeDevice", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)group_id, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "serialNumber", MBSTRING_ASC, (const unsigned char*)serial_number, -1, -1, 0);

    // 5. 使用私鑰對 CSR 進行簽章 (SHA-256)
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "❌ CSR 簽章失敗！");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return false;
    }

    // 6. 將 CSR 轉為二進位 (DER) 格式並放入 open62541 的 UA_ByteString 中
    int csr_len = i2d_X509_REQ(req, NULL);
    UA_ByteString_allocBuffer(&csrByteString, csr_len);
    unsigned char *p = csrByteString.data;
    i2d_X509_REQ(req, &p); // 注意：i2d 會移動指標，所以要傳遞指標的位址

    // 釋放 OpenSSL 物件 (此時資料已在 csrByteString 中)
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "✅ CSR 建立完成，準備向 Server 提交。");
    // -------------------------------------------------------------
    // 步驟 1: 配置 OPC UA Client 加密連線 (用出廠憑證建立安全通道)
    // -------------------------------------------------------------
    UA_Client *client = UA_Client_new();
    UA_ClientConfig *config = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(config);

    // 🌟 核心改變：我們直接用出廠憑證與出廠私鑰，作為連線的身分驗證！
    UA_ByteString initialCert = loadLocalFile("initial_client_cert.der");
    UA_ByteString initialKey = loadLocalFile("initial_client_key.der");
    
    // 👇 新增：載入 GDS 伺服器的 CA 憑證，建立信任清單
    UA_ByteString trustList[1];
    trustList[0] = loadLocalFile("ca_cert.der"); 
    size_t trustListSize = (trustList[0].length > 0) ? 1 : 0;
    if (initialCert.length > 0 && initialKey.length > 0) {
        config->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT; 
        
        // 👇 修正：把 trustList 跟 trustListSize 傳進去！
        UA_ClientConfig_setDefaultEncryption(config, initialCert, initialKey, 
                                             trustList, trustListSize, 
                                             NULL, 0);
                                             
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "🛡️ 已掛載出廠憑證與信任清單，準備建立安全通道...");
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

    // 1. CertificateGroupId
    UA_NodeId groupIdNode = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_Variant_setScalar(&inputStart[0], &groupIdNode, &UA_TYPES[UA_TYPES_NODEID]);

    // 2. CertificateTypeId
    UA_NodeId typeIdNode = UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_Variant_setScalar(&inputStart[1], &typeIdNode, &UA_TYPES[UA_TYPES_NODEID]);

    // 3. SubjectName (必須與 CSR 中的一致)
    char subject_buf[256];
    snprintf(subject_buf, sizeof(subject_buf), "CN=EdgeDevice, O=%s, SERIALNUMBER=%s", group_id, serial_number);
    UA_String subjectStr = UA_STRING(subject_buf);
    UA_Variant_setScalar(&inputStart[2], &subjectStr, &UA_TYPES[UA_TYPES_STRING]);

    // 4. SubjectAltName (OPC UA 標準要求的擴充屬性)
    UA_String subjectAltStr = UA_STRING("URI:urn:open62541.unconfigured.application");
    UA_Variant_setScalar(&inputStart[3], &subjectAltStr, &UA_TYPES[UA_TYPES_STRING]);

    // 5. CSR 數據
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

    // 取得非同步任務 ID
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
    UA_Boolean success = false;
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
    // 清理記憶體
    UA_ByteString_clear(&csrByteString);
    UA_ByteString_clear(&initialCert);
    UA_ByteString_clear(&initialKey);
    UA_ByteString_clear(&trustList[0]);
    system("rm temp_csr.der");
    
    if (outputStart) UA_Array_delete(outputStart, outputStartSize, &UA_TYPES[UA_TYPES_VARIANT]);
    if (outputFinish) UA_Array_delete(outputFinish, outputFinishSize, &UA_TYPES[UA_TYPES_VARIANT]);
    
    //UA_Client_disconnect(client);
    UA_Client_delete(client);
    return success;
}
