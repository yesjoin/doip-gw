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

# ---- M0：报文编解码库 ----
add_library(doip-codec STATIC src/DoIpCodec.cpp)
target_include_directories(doip-codec PUBLIC include)

# ---- M0 自测：字节层 ----
add_executable(codec-selftest tests/codec_selftest.cpp)
target_link_libraries(codec-selftest PRIVATE doip-codec)

# ---- M0 工具：把十六进制翻译成人话 ----
add_executable(doip-dump tools/doip_dump.cpp)
target_link_libraries(doip-dump PRIVATE doip-codec)

# ---------------------------------------------------------------------------
# 测试注册：ctest 一条命令跑全部（项目二 M6 的经验，一开始就接上）
# ---------------------------------------------------------------------------
enable_testing()
add_test(NAME doip-codec COMMAND codec-selftest)
set_tests_properties(doip-codec PROPERTIES LABELS unit)
