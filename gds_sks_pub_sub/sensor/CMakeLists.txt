cmake_minimum_required(VERSION 3.12)
project(ZTA_TSN_Sensor_Publisher C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# ─── 💡 核心修改：直接從系統搜尋 open62541 ───
find_library(OPEN62541_LIB NAMES open62541)
find_path(OPEN62541_INCLUDE_DIR NAMES open62541/server.h)

if(NOT OPEN62541_LIB OR NOT OPEN62541_INCLUDE_DIR)
    message(FATAL_ERROR "❌ 系統中找不到 open62541，請確認是否已安裝至系統目錄！")
endif()
# ─────────────────────────────────────────────

# -------------------------------------------------------------------------
# 設定你自己的程式碼
# -------------------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${OPEN62541_INCLUDE_DIR}  # 🌟 引入系統中 open62541 的標頭檔路徑
)

# 注意：這裡不需要再放 open62541.c 了！
add_executable(sensor_server
    sensor_server.c
    client_bootstrap.c
)

# ─── 💡 新增：讓執行檔一樣自動輸出到專案底下的 bin 資料夾 ───
set_target_properties(sensor_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

# -------------------------------------------------------------------------
# 連結函式庫
# -------------------------------------------------------------------------
target_link_libraries(sensor_server
    PRIVATE
    ${OPEN62541_LIB}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
    m
)

message(STATUS "🚀 ZTA Sensor 邊緣端專案配置成功！")