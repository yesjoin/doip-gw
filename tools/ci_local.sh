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

step "1/11 编译器"
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

step "2/11 配置（干净目录，等价于 CI 全新克隆）"
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

step "3/11 构建 -Wall -Wextra -Wpedantic $([ "$WERROR" -eq 1 ] && echo '+ -Werror')"
if cmake --build "$BUILD" -j"$(nproc)" > "$LOG/build.log" 2>&1; then
    ok "构建成功"
else
    bad "构建失败"
    grep -m 10 -E "error:|Error " "$LOG/build.log" | sed 's/^/      /'
fi
W=$(grep -c "warning:" "$LOG/build.log" 2>/dev/null) || W=0
[ "$W" -eq 0 ] && ok "零编译警告" || echo "[WARN] 有 $W 条编译警告"

step "4/11 自测（ctest）"
if (cd "$BUILD" && ctest --output-on-failure > "$LOG/ctest.log" 2>&1); then
    ok "ctest 全绿"
else
    bad "ctest 有失败"
    tail -n 30 "$LOG/ctest.log" | sed 's/^/      /'
fi
echo "      用例明细："
grep -E "^ *[0-9]+/[0-9]+ Test" "$LOG/ctest.log" | sed 's/^/      /' || true

step "5/11 工具冒烟：十六进制 → 人话"
OUT=$("$BUILD/doip-dump" "02 FD 80 01 00 00 00 07 0E 00 00 01 22 F1 90" 2>&1)
echo "$OUT" | grep -q "0x8001"               && ok "doip-dump 认出 0x8001"          || bad "doip-dump 没认出 0x8001"
echo "$OUT" | grep -q "ReadDataByIdentifier" && ok "doip-dump 认出 0x22 读 DID 服务" || bad "doip-dump 没认出 0x22"
echo "$OUT" | grep -q "0x0E00"               && ok "doip-dump 认出源地址 0x0E00"     || bad "doip-dump 没认出源地址"

step "6/11 端到端：实体 + 客户端走真 UDP（loopback，端口 13455）"
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

step "7/11 端到端：实体 + 客户端走真 TCP（loopback，端口 13456）"
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

step "8/11 端到端：真 CAN（vcan0 + 项目一的 ECU）"
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

step "9/11 第三方客户端对打（python doipclient，5 条验收硬指标）"
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

step "10/11 多 ECU 路由（vcan0 + 两台 ECU + 路由表）"
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

step "11/11 扩展帧（29 位 ID，一条总线上标准帧 + 扩展帧并存）"
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

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] && echo "本地这条腿全绿。" && exit 0
echo "先修红的，再推 Git。"
exit 1
