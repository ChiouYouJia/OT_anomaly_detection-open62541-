#include "common.h"
#include <stdio.h>
#include <stdlib.h>

/* 這是 open62541 官方標準的檔案讀取函式實作 */
UA_ByteString loadFile(const char *const path) {
    UA_ByteString fileContents = UA_BYTESTRING_NULL;
    
    // 以二進位唯讀模式開啟檔案
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        fprintf(stderr, "❌ 無法開啟檔案: %s\n", path);
        return fileContents;
    }
    
    // 取得檔案大小
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // 配置 open62541 的記憶體空間並讀取資料
    if(fileContents.length > 0) {
        fileContents.data = (UA_Byte *)UA_malloc(fileContents.length);
        if(fileContents.data) {
            size_t read = fread(fileContents.data, sizeof(UA_Byte), fileContents.length, fp);
            if(read != fileContents.length) {
                UA_ByteString_clear(&fileContents);
            }
        }
    }
    
    fclose(fp);
    return fileContents;
}
