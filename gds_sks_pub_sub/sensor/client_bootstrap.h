#ifndef CLIENT_BOOTSTRAP_H
#define CLIENT_BOOTSTRAP_H

/* * 建議改用標準的 open62541 模組化引入，
 * 若你的專案仍使用單一檔案編譯 (amalgamation)，可以保留 #include "open62541.h"
 */
#include <open62541/types.h> 

/* * 執行零信任 Bootstrap 與 OPC UA GDS 憑證簽發流程 (IEC 62541-12 標準)
 * * 核心流程說明:
 * 1. 於記憶體中動態生成 RSA-2048 私鑰與 CSR (憑證簽章請求)，零磁碟暫存。
 * 2. 讀取本地的 `initial_client_cert.der` 與 `initial_client_key.der` (出廠憑證/私鑰)。
 * 3. 透過上述出廠憑證，與 SKS 伺服器建立加密通道 (Secure Channel)，完成強身分驗證。
 * 4. 呼叫標準 StartSigningRequest 提交 CSR 獲取任務 ID。
 * 5. 呼叫標準 FinishSigningRequest 領取簽發完成的正式營運憑證。
 * * 參數:
 * sks_url:       SKS 伺服器的連線網址 (e.g., "opc.tcp://192.168.1.100:4840")
 * group_id:      設備所屬群組 (e.g., "Group_TSN")，將作為憑證的 Organization (O) 屬性
 * serial_number: 設備硬體序號 (e.g., "SN-001")，將作為憑證的 serialNumber 屬性，供 ZTA 黑名單審查
 * output_path:   換回來的正式營運憑證要儲存的檔案路徑 (e.g., "sensor_operational_cert.der")
 * * 回傳:
 * UA_TRUE  (簽發並儲存成功)
 * UA_FALSE (連線失敗、遭 SKS 拒絕、或檔案寫入失敗)
 */
UA_Boolean perform_sks_bootstrap(const char* sks_url,
                                 const char* group_id,
                                 const char* serial_number,
                                 const char* output_path);

#endif /* SKS_AUTH_H */
