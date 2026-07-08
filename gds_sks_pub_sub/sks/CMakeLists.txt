cmake_minimum_required(VERSION 3.14)
project(OpcUaSksServer)

# 1. 尋找 MbedTLS (因為 open62541 靜態庫與金鑰派發功能高度依賴其加密套件)
find_package(MbedTLS)

# 如果系統的 find_package 找不到 MbedTLS，手動定義傳統變數作為後備方案
if(NOT MbedTLS_FOUND)
    set(MbedTLS_LIBRARIES "mbedcrypto" "mbedx509" "mbedtls")
endif()

# 2. 產生執行檔 (假設你的主程式檔名叫做 sks_server.c)
# 這裡同時編譯了 sks_server.c 與共用的 common.c
add_executable(sks_server sks_server.c common.c)

set_target_properties(sks_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

# 3. 引入標頭檔搜尋路徑 (確保能抓到同目錄底下的 common.h)
target_include_directories(sks_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# 4. 連結所有需要的函式庫 (包含 open62541 以及 MbedTLS 加密庫)
target_link_libraries(sks_server 
    open62541 
    ${MbedTLS_LIBRARIES}
)
