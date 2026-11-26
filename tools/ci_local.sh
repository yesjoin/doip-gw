#!/usr/bin/env bash
# ============================================================================
# ci_local.sh —— 在本地把 CI 的每一步原样跑一遍（M2 版）
#
# 用法：bash tools/ci_local.sh [gcc|clang]
# 环境变量：BUILD=build-ci（默认，不覆盖你平时的 build/）
# ============================================================================
set -u
cd "$(dirname "$0")/.." || exit 1

CC_NAME=${1:-gcc}
BUILD=${BUILD:-build-ci}

pass=0
fail=0
ok()  { echo "[PASS] $1"; pass=$((pass + 1)); }
bad() { echo "[FAIL] $1"; fail=$((fail + 1)); }
step() { printf '\n=== %s ===\n' "$1"; }

LOG=$(mktemp -d)
trap 'rm -rf "$LOG"' EXIT

step "1/30 编译器"
if [ "$CC_NAME" = clang ]; then
    export CC=clang CXX=clang++
    WERROR=0
else
    export CC=gcc CXX=g++
    WERROR=1
fi
echo "      CC=$CC  CXX=$CXX"
if ! command -v "$CXX" > /dev/null 2>&1; then
    echo "[SKIP] 这台机器上没有 $CXX。跳过这条腿。"
    exit 0
fi
$CXX --version | head -1 | sed 's/^/      /'

step "2/30 配置（干净目录，等价于 CI 全新克隆）"
rm -rf "$BUILD"
EXTRA=""
[ "$WERROR" -eq 1 ] && EXTRA="-DDOIP_WERROR=ON"
# -O2 是故意的：有些警告只在优化后才出现（glibc 的 warn_unused_result 就是一例，
# Debug 的 -O0 下它不报，Release 一编就红）。CI 不模拟这一层，等于把 bug 留给用户。
echo "      cmake -S . -B $BUILD -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS=-O2 $EXTRA"
if cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS=-O2 $EXTRA > "$LOG/cfg.log" 2>&1; then
    ok "cmake 配置成功"
else
    bad "cmake 配置失败"
    tail -n 15 "$LOG/cfg.log" | sed 's/^/      /'
fi

step "3/30 构建 -Wall -Wextra -Wpedantic $([ "$WERROR" -eq 1 ] && echo '+ -Werror')"
if cmake --build "$BUILD" -j"$(nproc)" > "$LOG/build.log" 2>&1; then
    ok "构建成功"
else
    bad "构建失败"
    grep -m 10 -E "error:|Error " "$LOG/build.log" | sed 's/^/      /'
fi
W=$(grep -c "warning:" "$LOG/build.log" 2>/dev/null) || W=0
[ "$W" -eq 0 ] && ok "零编译警告" || echo "[WARN] 有 $W 条编译警告"

step "4/30 自测（ctest）"
if (cd "$BUILD" && ctest --output-on-failure > "$LOG/ctest.log" 2>&1); then
    ok "ctest 全绿"
else
    bad "ctest 有失败"
    tail -n 30 "$LOG/ctest.log" | sed 's/^/      /'
fi
echo "      用例明细："
grep -E "^ *[0-9]+/[0-9]+ Test" "$LOG/ctest.log" | sed 's/^/      /' || true

step "5/30 工具冒烟：十六进制 → 人话"
OUT=$("$BUILD/doip-dump" "02 FD 80 01 00 00 00 07 0E 00 00 01 22 F1 90" 2>&1)
echo "$OUT" | grep -q "0x8001"               && ok "doip-dump 认出 0x8001"          || bad "doip-dump 没认出 0x8001"
echo "$OUT" | grep -q "ReadDataByIdentifier" && ok "doip-dump 认出 0x22 读 DID 服务" || bad "doip-dump 没认出 0x22"
echo "$OUT" | grep -q "0x0E00"               && ok "doip-dump 认出源地址 0x0E00"     || bad "doip-dump 没认出源地址"

step "6/30 端到端：实体 + 客户端走真 UDP（loopback，端口 13455）"
"$BUILD/doip-discover" --serve --port 13455 --seconds 3 > "$LOG/serve.log" 2>&1 &
SRV=$!
sleep 0.4
if "$BUILD/doip-discover" --host 127.0.0.1 --port 13455 --wait-ms 800 > "$LOG/client.log" 2>&1; then
    ok "客户端收到了实体的应答"
else
    bad "客户端没收到应答"
    cat "$LOG/client.log" | sed 's/^/      /'
fi
wait $SRV || true
grep -q "VIN=LSVAA20A8F2100001" "$LOG/client.log" && ok "应答里的 VIN 正确" || bad "应答里的 VIN 不对"
grep -q "回了 1 个应答" "$LOG/serve.log"          && ok "实体侧日志确认回了 1 个" || bad "实体侧没记录到应答"
echo "      --- 客户端看到 ---"
head -4 "$LOG/client.log" | sed 's/^/      /'

step "7/30 端到端：实体 + 客户端走真 TCP（loopback，端口 13456）"
# 心跳周期调到 5000ms：这条用例要的是"能激活、心跳能一问一答"，
# 不让服务器主动发心跳来抢戏（那条逻辑由 routing-selftest 用 150ms 单独测）。
"$BUILD/doip-serve" --port 13456 --seconds 4 --idle-ms 5000 > "$LOG/tcpserve.log" 2>&1 &
TCP=$!
sleep 0.4
if "$BUILD/doip-client" --host 127.0.0.1 --port 13456 --sa 0E00 --alive --diag "22 F1 86" > "$LOG/tcpclient.log" 2>&1; then
    ok "客户端走完 连接→激活→心跳→诊断"
else
    bad "客户端 TCP 流程失败"
    cat "$LOG/tcpclient.log" | sed 's/^/      /'
fi
wait $TCP || true
grep -q "code=0x10"      "$LOG/tcpclient.log" && ok "0x0006 应答码 0x10（激活成功）" || bad "应答码不是 0x10"
grep -q "0x0008 心跳应答" "$LOG/tcpclient.log" && ok "0x0007 问到了 0x0008"           || bad "心跳没应答"
grep -q "0x8002 ACK"     "$LOG/tcpclient.log" && ok "诊断收到 0x8002 回执"            || bad "没有 0x8002 回执"
grep -q "UDS=62 F1 86 01" "$LOG/tcpclient.log" && ok "诊断响应 62 F1 86 01"           || bad "诊断响应不对"
grep -q "成功激活 1 次"    "$LOG/tcpserve.log"  && ok "实体侧确认激活 1 次"             || bad "实体侧没记录到激活"
echo "      --- 客户端看到 ---"
head -8 "$LOG/tcpclient.log" | sed 's/^/      /'

step "8/30 端到端：真 CAN（vcan0 + 项目一的 ECU）"
# 这一步需要真总线 + 项目一的 uds-demo。CI 的 GitHub runner 上没有，
# 所以只在装了 CAN 的机器上跑；缺东西就 SKIP，不算红。
if [ -d /sys/class/net/vcan0 ] && [ -x "$HOME/uds-ecu/build/uds-demo" ]; then
    pkill -x uds-demo 2>/dev/null || true
    sleep 0.2
    "$HOME/uds-ecu/build/uds-demo" --ecu --iface vcan0 --wait-s 8 > "$LOG/ecu.log" 2>&1 &
    ECU=$!
    sleep 0.4
    "$BUILD/doip-gateway" --iface vcan0 --port 13458 --seconds 6 > "$LOG/gw.log" 2>&1 &
    GW=$!
    sleep 0.4

    if "$BUILD/doip-client" --port 13458 --sa 0E00 --diag "22 F1 90" > "$LOG/can1.log" 2>&1; then
        ok "以太网 22 F1 90 穿到 CAN 并拿到响应"
    else
        bad "22 F1 90 穿过网关失败"
        cat "$LOG/can1.log" | sed 's/^/      /'
    fi
    grep -q "UDS=62 F1 90 4C 53 56" "$LOG/can1.log" && ok "响应是 20 字节 VIN（ECU 侧多帧）" || bad "VIN 响应不对"

    if "$BUILD/doip-client" --port 13458 --sa 0E00 --diag "3E 00" > "$LOG/can2.log" 2>&1; then
        ok "3E 00 短请求也能通"
    else
        bad "3E 00 失败"
        cat "$LOG/can2.log" | sed 's/^/      /'
    fi
    grep -q "UDS=7E 00" "$LOG/can2.log" && ok "3E 00 → 7E 00" || bad "3E 00 响应不对"

    wait $GW || true
    kill $ECU 2>/dev/null || true
    grep -q "转发 2 条，失败 0 条" "$LOG/gw.log" && ok "网关转发 2 条、0 失败" || bad "网关转发统计不对"
else
    echo "[SKIP] 没有 vcan0 或没有 ~/uds-ecu/build/uds-demo，跳过真 CAN 这一步"
fi

step "9/30 第三方客户端对打（python doipclient，5 条验收硬指标）"
# 为什么单独拎一步：前面所有测试都是"自己写的东西测自己写的东西"，
# 这一步换成别人按标准写的客户端，能过才说明符合标准。
# doipclient 是 pip 包，GitHub runner 上没装 → SKIP，不算红。
if python3 -c 'import doipclient' >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m5_e2e.sh" 13459 > "$LOG/m5.log" 2>&1; then
        ok "第三方客户端：5 条硬指标全绿"
    else
        bad "第三方客户端对打失败"
        tail -n 25 "$LOG/m5.log" | sed 's/^/      /'
    fi
    grep -E "^(发现|接入|转发|ISO-TP)" "$LOG/m5.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 没装第三方客户端（pip3 install --user doipclient）"
fi

step "10/30 多 ECU 路由（vcan0 + 两台 ECU + 路由表）"
# 这一步要两台 ECU：项目一的 uds-demo（7E0/7E8）+ 本仓库的 stub-ecu（7A0/7A8）。
# 缺任何一样就 SKIP。
if [ -d /sys/class/net/vcan0 ] && [ -x "$HOME/uds-ecu/build/uds-demo" ] && [ -x "$BUILD/stub-ecu" ] \
   && python3 -c 'import doipclient' >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m6_e2e.sh" 13462 > "$LOG/m6.log" 2>&1; then
        ok "多 ECU 路由：TA 打到两台不同 ECU，未知地址回 0x03"
    else
        bad "多 ECU 路由失败"
        tail -n 25 "$LOG/m6.log" | sed 's/^/      /'
    fi
    grep -E "^(通过|转发|  TA=)" "$LOG/m6.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / uds-demo / stub-ecu / doipclient，跳过路由验收"
fi

step "11/30 扩展帧（29 位 ID，一条总线上标准帧 + 扩展帧并存）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$HOME/uds-ecu/build/uds-demo" ] && [ -x "$BUILD/stub-ecu" ] \
   && command -v candump >/dev/null 2>&1 && python3 -c 'import doipclient' >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m7_e2e.sh" 13463 > "$LOG/m7.log" 2>&1; then
        ok "扩展帧：同一张路由表里 11 位 / 29 位都能走"
    else
        bad "扩展帧端到端失败"
        tail -n 25 "$LOG/m7.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m7.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / uds-demo / stub-ecu / candump / doipclient，跳过扩展帧验收"
fi

step "12/30 功能寻址（一条广播 → 多台 ECU 应答，SA 各不相同）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] \
   && command -v candump >/dev/null 2>&1 && python3 -c 'import doipclient' >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m8_e2e.sh" 13464 > "$LOG/m8.log" 2>&1; then
        ok "功能寻址：0xE400 → 7DF，两台 ECU 各答一句且分得清是谁"
    else
        bad "功能寻址端到端失败"
        tail -n 25 "$LOG/m8.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m8.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / candump / doipclient，跳过功能寻址验收"
fi

step "13/30 CAN FD（同一套 ISO-TP，经典帧 8 字节 vs FD 帧 64 字节）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] \
   && command -v candump >/dev/null 2>&1 && python3 -c 'import doipclient' >/dev/null 2>&1 \
   && [ "$(cat /sys/class/net/vcan0/mtu 2>/dev/null || echo 0)" -ge 72 ]; then
    if bash "$(dirname "$0")/m9_e2e.sh" 13465 > "$LOG/m9.log" 2>&1; then
        ok "CAN FD：200 字节 FD 4 帧 / 经典 29 帧，内容逐字节相同"
    else
        bad "CAN FD 端到端失败"
        tail -n 25 "$LOG/m9.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m9.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / MTU<72 / stub-ecu / candump / doipclient，跳过 CAN FD 验收"
fi

step "14/30 多 tester 独立通道（一条通道一条队列 + 一条线程）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && [ -x "$BUILD/doip-gateway" ] \
   && command -v candump >/dev/null 2>&1 && python3 -c 'import doipclient' >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m10_e2e.sh" 13466 > "$LOG/m10.log" 2>&1; then
        ok "多 tester：慢 ECU 只慢自己那条通道，同一通道两个 tester 排队不交叉"
    else
        bad "多 tester 端到端失败"
        tail -n 25 "$LOG/m10.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m10.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / doip-gateway / candump / doipclient，跳过多 tester 验收"
fi

step "15/30 多响应配对（一条广播，三台 ECU 各答一句，按 SA 归档）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && [ -x "$BUILD/doip-client" ] \
   && command -v candump >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m11_e2e.sh" 13467 13468 > "$LOG/m11.log" 2>&1; then
        ok "多响应配对：三条答案按 SA 归档，静默窗口收工，短窗口不串味"
    else
        bad "多响应配对端到端失败"
        tail -n 25 "$LOG/m11.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m11.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / doip-client / candump，跳过多响应配对验收"
fi

step "16/30 流式交付（收一条转一条，同一 job 不重发）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && [ -x "$BUILD/doip-client" ] \
   && command -v candump >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m12_e2e.sh" 13469 13470 > "$LOG/m12.log" 2>&1; then
        ok "流式交付：首条不再等最慢那台，交卷只补差额（DUPLICATES=0）"
    else
        bad "流式交付端到端失败"
        tail -n 25 "$LOG/m12.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m12.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / doip-client / candump，跳过流式交付验收"
fi

step "17/30 实体级 tester 地址仲裁（同址 0x03 / 名额 0x01 / 断开即释放）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m13_e2e.sh" 13471 > "$LOG/m13.log" 2>&1; then
        ok "地址仲裁：同址冲突被拒、名额满被拒、释放后地址能要回来"
    else
        bad "地址仲裁端到端失败"
        tail -n 25 "$LOG/m13.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m13.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳过地址仲裁验收"
fi

step "18/30 实体状态与电源模式（0x4001/0x4003 只走 UDP，cur 数 socket 不数激活）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m14_e2e.sh" 13472 > "$LOG/m14.log" 2>&1; then
        ok "实体状态：0x4002 四个字段与实现一致、不合规用法沉默、电源模式跟着配置"
    else
        bad "实体状态端到端失败"
        tail -n 25 "$LOG/m14.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m14.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳过实体状态验收"
fi

step "19/30 UDS 刷写链路（0x31 擦除 → 0x34 → 0x36 → 0x37 → 0x31 校验，BSC 跳号/重发/块长）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m15_e2e.sh" 13474 > "$LOG/m15.log" 2>&1; then
        ok "刷写链路：状态机的顺序/长度/跳号各有各的码，重发幂等，CRC 对得上"
    else
        bad "刷写链路端到端失败"
        tail -n 30 "$LOG/m15.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m15.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳过刷写链路验收"
fi

step "20/30 会话门禁（0x10 会话 + 0x27 种子/密钥 + S3 超时 + 错 3 次锁 10 秒）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m16_e2e.sh" 13475 > "$LOG/m16.log" 2>&1; then
        ok "会话门禁：会话不对 0x7F / 没解锁 0x33 / 换会话清锁 / S3 回落 / 错 3 次锁"
    else
        bad "会话门禁端到端失败"
        tail -n 30 "$LOG/m16.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m16.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳过会话门禁验收"
fi

step "21/30 0x11 复位（硬清镜像 / 软留镜像 / 刷写中途 0x22 / 默认会话也可复位）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m17_e2e.sh" 13477 > "$LOG/m17.log" 2>&1; then
        ok "复位：51 xx 先回后动 / 刷写中途 22 / 软复位留镜像 / 硬复位清镜像"
    else
        bad "复位端到端失败"
        tail -n 30 "$LOG/m17.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m17.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳过复位验收"
fi
step "22/30 刷写包完整性（SHA-256 + 清单 v1/v2 + 标签；结构错 NRC / 内容错 01 / 换包被抓）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m18_e2e.sh" 13479 > "$LOG/m18.log" 2>&1; then
        ok "完整性：哈希+标签 / 换包被抓 / 结构错 13·31 / 内容错 01 / 空镜像 22"
    else
        bad "完整性端到端失败"
        tail -n 30 "$LOG/m18.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m18.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳过完整性验收"
fi

step "23/30 刷写前置条件（0x22 读身份 / 0x2E 写指纹 / 0x31 01 0203 检查 / 电压不够 0x34 回 22）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m19_e2e.sh" 13481 13482 > "$LOG/m19.log" 2>&1; then
        ok "前置条件：读 F187/F188/F18C/F1A5/F184 / 写指纹拦三道 7F·33·13·31 / 00 与 01 / 11000 mV 回 22"
    else
        bad "前置条件端到端失败"
        tail -n 30 "$LOG/m19.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m19.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳前置条件验收"
fi

step "24/30 包与车对不对得上（0x31 01 0204 零件号+版本 / 0x34 要凭证且一次一用 / 版本按数值比）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m20_e2e.sh" 13483 13484 > "$LOG/m20.log" 2>&1; then
        ok "兼容性：零件号 01 / 降级 01 / 同版本 00 / 1.10.0 判升级 / 凭证不检查也拒 22 / 擦除与收尾作废凭证"
    else
        bad "兼容性端到端失败"
        tail -n 30 "$LOG/m20.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m20.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳兼容性验收"
fi

step "25/30 清单里带身份（0x31 01 0205 只收 v2 / 身份在标签下面改不了 / FF02 包真≠给这台车回 02）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m21_e2e.sh" 13485 13486 > "$LOG/m21.log" 2>&1; then
        ok "身份：v1 拒 31 / 长度 13 / 版本不配对 31 / 标签不符 31 / 身份不符 01 / 旧凭证 22 / FF02 00与02 / 无镜像也能预检"
    else
        bad "清单身份端到端失败"
        tail -n 30 "$LOG/m21.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m21.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳清单身份验收"
fi

step "26/30 钥匙表（0x22 F1B0 读表 / 0206 装钥匙 / 0207 退役·吊销 / 退役照验·吊销拒收且终态）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m22_e2e.sh" 13487 13488 > "$LOG/m22.log" 2>&1; then
        ok "钥匙：读表 / 装 3 / 不许覆盖 01 / 退役照验 00 / 吊销拒收 31 / 终态 01 / 复位后装钥匙 7F 而读表照读"
    else
        bad "钥匙表端到端失败"
        tail -n 30 "$LOG/m22.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m22.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳钥匙表验收"
fi

step "27/30 钥匙表落盘（重启后吊销还在 / 坏文件不猜回默认 / 半截表不许再写 / 重建要人说话）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m23_e2e.sh" 13489 13490 > "$LOG/m23.log" 2>&1; then
        ok "落盘：首启建表 / 装 3 号 / 吊销 1 号 / 重启仍是 02 / 1 号包被拒 / 坏文件表空且装钥匙 22 / --reset 后回默认"
    else
        bad "钥匙表落盘端到端失败"
        tail -n 30 "$LOG/m23.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m23.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / python3，跳钥匙表落盘验收"
fi
step "28/30 车队钥匙清单（广播只能投票 / 搬数据要逐台 / 核对靠摘要 / 部分成功要点名）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && [ -x "$BUILD/doip-gateway" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m24_e2e.sh" 13491 13492 > "$LOG/m24.log" 2>&1; then
        ok "车队：广播摘要 3 台一致 / 广播装钥匙被拒 0x04 / 020A 表决 / 逐台 0206 装 / 退役即分叉 / 一起吊销 3-1-1-1 / 坏表 2 成 1 拒并点名 0006"
    else
        bad "车队钥匙清单端到端失败"
        tail -n 30 "$LOG/m24.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m24.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / doip-gateway / python3，跳车队钥匙清单验收"
fi

step "29/30 清单指纹与世代（0x22 F1B2 抓假一致 / 世代活过重启 / 内容回原样但历史不同 / 写新读旧）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && [ -x "$BUILD/doip-gateway" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m25_e2e.sh" 13494 13495 > "$LOG/m25.log" 2>&1; then
        ok "指纹：摘要 4/4 三台一样但指纹点出 0006 / 世代 2 活过重启 / 退役再回原样指纹复原而世代到 4 / v1 旧文件读成 0 且指纹不变"
    else
        bad "清单指纹与世代端到端失败"
        tail -n 30 "$LOG/m25.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m25.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / doip-gateway / python3，跳清单指纹与世代验收"
fi

step "30/30 变更流水（出厂「没有变更」说得出口 / 六件事记全 / 广播与逐台分得开 / 时间不骗人）"
if [ -d /sys/class/net/vcan0 ] && [ -x "$BUILD/stub-ecu" ] && [ -x "$BUILD/doip-gateway" ] && command -v python3 >/dev/null 2>&1; then
    if bash "$(dirname "$0")/m26_e2e.sh" 13496 13497 > "$LOG/m26.log" 2>&1; then
        ok "流水：F1B3 出厂 0 条 / 装一把记世代 1 / 广播退役通道 02 / 复活动作 03 / 重启后新账第 2 次上电而旧账仍第 1 次 / 降级 v2 流水空且横幅喊出来"
    else
        bad "变更流水端到端失败"
        tail -n 30 "$LOG/m26.log" | sed 's/^/      /'
    fi
    grep -E "^通过 " "$LOG/m26.log" | sed 's/^/      /' || true
else
    echo "[SKIP] 缺 vcan0 / stub-ecu / doip-gateway / python3，跳变更流水验收"
fi

echo ""
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] && echo "本地这条腿全绿。" && exit 0
echo "先修红的，再推 Git。"
exit 1
