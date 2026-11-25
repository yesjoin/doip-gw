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

# ---- M6：路由表（TA → CAN 收发 ID），纯逻辑 ----
# M7 起把 CanId 也挂在这里：宽度判断（11 位 / 29 位 + CAN_EFF_FLAG）是纯计算，
# 塞进 doip-route 而不是 doip-isotp，是因为自测不需要 socket 就能把它测完
add_library(doip-route STATIC src/RouteTable.cpp src/CanId.cpp)
target_include_directories(doip-route PUBLIC include)
target_link_libraries(doip-isotp PUBLIC doip-route)

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

# ---- M6 自测（路由表 + "目标地址不认识就拒" 的通道语义，纯逻辑）----
add_executable(route-selftest tests/route_selftest.cpp)
target_link_libraries(route-selftest PRIVATE doip-route doip-diag doip-codec)

# ---- M10 自测（排队与交卷台的纯逻辑：FIFO / 容量 / stop / 作废）----
add_executable(collector-selftest tests/collector_selftest.cpp)
target_include_directories(collector-selftest PRIVATE include)

add_executable(pool-selftest tests/pool_selftest.cpp)
target_link_libraries(pool-selftest PRIVATE doip-diag Threads::Threads)

# M12：流式交付的记账（纯逻辑，不链任何 socket 库）
add_executable(stream-selftest tests/stream_selftest.cpp)
target_include_directories(stream-selftest PRIVATE include)

# M13：实体级 tester 地址仲裁（纯逻辑：两张 map，不碰 socket）
add_executable(registry-selftest tests/registry_selftest.cpp)
target_include_directories(registry-selftest PRIVATE include)

# M14：实体状态 / 电源模式（纯逻辑：只做 7 字节编解码和两条请求的判据）
# 故意不链 doip-discovery：这一层就不该知道 socket 存在，自测也就不需要端口
add_executable(entity-selftest tests/entity_selftest.cpp)
target_link_libraries(entity-selftest PRIVATE doip-codec)
target_include_directories(entity-selftest PRIVATE include)

# M15：刷写状态机（纯逻辑：BSC 回绕、重发幂等、长度与顺序判据、CRC-32）
add_executable(flash-selftest tests/flash_selftest.cpp)
target_include_directories(flash-selftest PRIVATE include)

# M16：会话层（0x10 / 0x27 / 0x3E / S3）—— 时间当参数传，自测不用 sleep
add_executable(session-selftest tests/session_selftest.cpp)
target_include_directories(session-selftest PRIVATE include)

# M17：0x11 复位 × 会话状态机 × 镜像语义（硬复位清镜像、软复位留镜像）
add_executable(reset-selftest tests/reset_selftest.cpp)
target_include_directories(reset-selftest PRIVATE include)

# M18：SHA-256（标准向量）+ 刷写包清单/标签（结构错 vs 内容错）
add_executable(integrity-selftest tests/integrity_selftest.cpp)
target_include_directories(integrity-selftest PRIVATE include)

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
# doip-route：M6 的路由表（经 doip-isotp 传递进来）
target_link_libraries(doip-gateway PRIVATE doip-tcp doip-isotp doip-discovery doip-route Threads::Threads)

# ---- M6：第二台 ECU（真 SocketCAN 节点，用来验证路由打到不同地址）----
add_executable(stub-ecu tools/stub_ecu.cpp)
target_link_libraries(stub-ecu PRIVATE doip-isotp Threads::Threads)
target_include_directories(stub-ecu PRIVATE include)   # M15：FlashTarget.h

# ---------------------------------------------------------------------------
# 测试注册：ctest 一条命令跑全部
# ---------------------------------------------------------------------------
enable_testing()
add_test(NAME doip-codec     COMMAND codec-selftest)
add_test(NAME doip-discovery COMMAND discovery-selftest)
add_test(NAME doip-routing   COMMAND routing-selftest)
add_test(NAME doip-diagnostic COMMAND diagnostic-selftest)
add_test(NAME doip-isotp     COMMAND isotp-selftest)
add_test(NAME doip-route     COMMAND route-selftest)
add_test(NAME doip-pool      COMMAND pool-selftest)
add_test(NAME doip-collector COMMAND collector-selftest)
add_test(NAME doip-stream    COMMAND stream-selftest)
add_test(NAME doip-registry  COMMAND registry-selftest)
add_test(NAME doip-entity    COMMAND entity-selftest)
add_test(NAME doip-flash     COMMAND flash-selftest)
add_test(NAME doip-session   COMMAND session-selftest)
add_test(NAME doip-reset     COMMAND reset-selftest)
add_test(NAME doip-integrity COMMAND integrity-selftest)
set_tests_properties(doip-codec doip-discovery doip-routing doip-diagnostic doip-isotp doip-route doip-pool doip-collector doip-stream doip-registry doip-entity doip-flash doip-session doip-reset doip-integrity PROPERTIES LABELS unit)
