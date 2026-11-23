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

# ---- M2：路由激活状态机（纯逻辑，每个连接一个实例）----
add_library(doip-routing STATIC src/DoIpRouting.cpp)
target_link_libraries(doip-routing PUBLIC doip-codec)

# ---- M2：TCP 13400 服务器（收字节、拼报文、心跳）----
add_library(doip-tcp STATIC src/DoIpTcpServer.cpp)
target_link_libraries(doip-tcp PUBLIC doip-routing doip-codec Threads::Threads)

# ---- M3：诊断报文通道（0x8001 校验 + 0x8002/0x8003 回执 + 下游接口）----
add_library(doip-diag STATIC src/DoIpDiagnostic.cpp)
target_link_libraries(doip-diag PUBLIC doip-codec)
target_link_libraries(doip-tcp PUBLIC doip-diag)

# ---- M4：ISO-TP（拆帧/重组纯逻辑 + SocketCAN 客户端 + 网关桥接）----
add_library(doip-isotp STATIC src/IsoTpStack.cpp src/IsoTpClient.cpp src/DoIpGateway.cpp)
target_link_libraries(doip-isotp PUBLIC doip-diag Threads::Threads)

# ---- M0 自测 ----
add_executable(codec-selftest tests/codec_selftest.cpp)
target_link_libraries(codec-selftest PRIVATE doip-codec)

# ---- M1 自测（用了 std::thread 起服务器，所以要 pthread）----
add_executable(discovery-selftest tests/discovery_selftest.cpp)
target_link_libraries(discovery-selftest PRIVATE doip-discovery Threads::Threads)

# ---- M2 自测（A 段纯逻辑 + B 段真 TCP）----
add_executable(routing-selftest tests/routing_selftest.cpp)
target_link_libraries(routing-selftest PRIVATE doip-tcp Threads::Threads)

# ---- M3 自测（A 段纯逻辑 + B 段真 TCP 全链路）----
add_executable(diagnostic-selftest tests/diagnostic_selftest.cpp)
target_link_libraries(diagnostic-selftest PRIVATE doip-tcp Threads::Threads)

# ---- M4 自测（纯逻辑：拆帧/重组/流控/往返，不需要 vcan0）----
add_executable(isotp-selftest tests/isotp_selftest.cpp)
target_link_libraries(isotp-selftest PRIVATE doip-isotp Threads::Threads)

# ---- 工具 ----
add_executable(doip-dump tools/doip_dump.cpp)
target_link_libraries(doip-dump PRIVATE doip-codec)

add_executable(doip-discover tools/doip_discover.cpp)
target_link_libraries(doip-discover PRIVATE doip-discovery Threads::Threads)

add_executable(doip-serve tools/doip_serve.cpp)
target_link_libraries(doip-serve PRIVATE doip-tcp Threads::Threads)

add_executable(doip-client tools/doip_client.cpp)
target_link_libraries(doip-client PRIVATE doip-routing doip-diag Threads::Threads)

add_executable(doip-gateway tools/doip_gateway.cpp)
# doip-discovery：M5 起网关也要回答 UDP 车辆发现（真实实体发现和激活是同一个端口号）
target_link_libraries(doip-gateway PRIVATE doip-tcp doip-isotp doip-discovery Threads::Threads)

# ---------------------------------------------------------------------------
# 测试注册：ctest 一条命令跑全部
# ---------------------------------------------------------------------------
enable_testing()
add_test(NAME doip-codec     COMMAND codec-selftest)
add_test(NAME doip-discovery COMMAND discovery-selftest)
add_test(NAME doip-routing   COMMAND routing-selftest)
add_test(NAME doip-diagnostic COMMAND diagnostic-selftest)
add_test(NAME doip-isotp     COMMAND isotp-selftest)
set_tests_properties(doip-codec doip-discovery doip-routing doip-diagnostic doip-isotp PROPERTIES LABELS unit)
