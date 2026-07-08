#ifndef COMMON_H
#define COMMON_H

#include <open62541/server.h>

/* 宣告讀取檔案的函式，讓 gds_server.c 可以順利呼叫 */
UA_ByteString loadFile(const char *const path);

#endif /* COMMON_H */
