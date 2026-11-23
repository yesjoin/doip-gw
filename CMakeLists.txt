cmake_minimum_required(VERSION 3.16)
project(doip_gw LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic)

# CI 里把警告升级成错误（项目二沿用的做法：让"零警告"变成机器检查的结论）
option(DOIP_WERROR "把编译警告当错误（-Werror），CI 用" OFF)
if(DOIP_WERROR)
    add_compile_options(-Werror)
endif()

find_package(Threads REQUIRED)

# ---- M0：报文编解码库（纯逻辑，不碰 socket）----
add_library(doip-codec STATIC src/DoIpCodec.cpp)
target_include_directories(doip-codec PUBLIC include)

# ---- M1：发现层（应答逻辑 + UDP 服务器）----
add_library(doip-discovery STATIC src/DoIpDiscovery.cpp)
target_link_libraries(doip-discovery PUBLIC doip-codec)

# ---- M0 自测 ----
add_executable(codec-selftest tests/codec_selftest.cpp)
target_link_libraries(codec-selftest PRIVATE doip-codec)

# ---- M1 自测（用了 std::thread 起服务器，所以要 pthread）----
add_executable(discovery-selftest tests/discovery_selftest.cpp)
target_link_libraries(discovery-selftest PRIVATE doip-discovery Threads::Threads)

# ---- 工具 ----
add_executable(doip-dump tools/doip_dump.cpp)
target_link_libraries(doip-dump PRIVATE doip-codec)

add_executable(doip-discover tools/doip_discover.cpp)
target_link_libraries(doip-discover PRIVATE doip-discovery Threads::Threads)

# ---------------------------------------------------------------------------
# 测试注册：ctest 一条命令跑全部
# ---------------------------------------------------------------------------
enable_testing()
add_test(NAME doip-codec     COMMAND codec-selftest)
add_test(NAME doip-discovery COMMAND discovery-selftest)
set_tests_properties(doip-codec doip-discovery PROPERTIES LABELS unit)
