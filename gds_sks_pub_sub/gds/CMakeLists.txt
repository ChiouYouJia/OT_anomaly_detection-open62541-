cmake_minimum_required(VERSION 3.14)
project(MyOpcUaServer)

# 1. 尋找 SQLite3
find_package(SQLite3 REQUIRED)

# 2. 尋找 MbedTLS 
find_package(MbedTLS)
if(NOT MbedTLS_FOUND)
    set(MbedTLS_LIBRARIES "mbedcrypto" "mbedx509" "mbedtls")
endif()

# 3. 產生執行檔
add_executable(gds_server gds_server.c common.c)

# ─── 💡 新增這行：設定執行檔輸出路徑 ───
set_target_properties(gds_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

# 4. 加上標頭檔路徑
target_include_directories(gds_server PRIVATE ${SQLite3_INCLUDE_DIRS})

# 5. 連結所有需要的函式庫
target_link_libraries(gds_server 
    open62541 
    ${SQLite3_LIBRARIES}
    ${MbedTLS_LIBRARIES}
)