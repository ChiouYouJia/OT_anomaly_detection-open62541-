cmake_minimum_required(VERSION 3.12)
project(ZTA_TSN_Motor_Subscriber C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# -------------------------------------------------------------------------
# 1. 偵測樹莓派硬體控制庫 (lgpio)
# -------------------------------------------------------------------------
find_library(LGPIO_LIB NAMES lgpio)
if(NOT LGPIO_LIB)
    message(FATAL_ERROR "❌ 找不到 lgpio 函式庫！請確認馬達端樹莓派已安裝 liblgpio-dev\n指令: sudo apt install liblgpio-dev")
endif()

# -------------------------------------------------------------------------
# 2. 設定專案路徑與編譯目標
# -------------------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

add_executable(motor_server
    motor_server.c
    client_bootstrap.c
)

set_target_properties(motor_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

# -------------------------------------------------------------------------
# 3. 連結外部資源庫 (包含 OpenSSL 與特殊的 lgpio)
# -------------------------------------------------------------------------
target_link_libraries(motor_server
    PRIVATE
    ${OPENSSL_LIBRARIES}
    ${LGPIO_LIB}            # 🌟 掛載馬達 PWM 輸出需要的 lgpio
    Threads::Threads
    m
)

message(STATUS "🚀 ZTA Motor 邊緣端專案配置成功！")