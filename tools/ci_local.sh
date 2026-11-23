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

step "1/7 编译器"
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

step "2/7 配置（干净目录，等价于 CI 全新克隆）"
rm -rf "$BUILD"
EXTRA=""
[ "$WERROR" -eq 1 ] && EXTRA="-DDOIP_WERROR=ON"
echo "      cmake -S . -B $BUILD -DCMAKE_BUILD_TYPE=Debug $EXTRA"
if cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug $EXTRA > "$LOG/cfg.log" 2>&1; then
    ok "cmake 配置成功"
else
    bad "cmake 配置失败"
    tail -n 15 "$LOG/cfg.log" | sed 's/^/      /'
fi

step "3/7 构建 -Wall -Wextra -Wpedantic $([ "$WERROR" -eq 1 ] && echo '+ -Werror')"
if cmake --build "$BUILD" -j"$(nproc)" > "$LOG/build.log" 2>&1; then
    ok "构建成功"
else
    bad "构建失败"
    grep -m 10 -E "error:|Error " "$LOG/build.log" | sed 's/^/      /'
fi
W=$(grep -c "warning:" "$LOG/build.log" 2>/dev/null) || W=0
[ "$W" -eq 0 ] && ok "零编译警告" || echo "[WARN] 有 $W 条编译警告"

step "4/7 自测（ctest）"
if (cd "$BUILD" && ctest --output-on-failure > "$LOG/ctest.log" 2>&1); then
    ok "ctest 全绿"
else
    bad "ctest 有失败"
    tail -n 30 "$LOG/ctest.log" | sed 's/^/      /'
fi
echo "      用例明细："
grep -E "^ *[0-9]+/[0-9]+ Test" "$LOG/ctest.log" | sed 's/^/      /' || true

step "5/7 工具冒烟：十六进制 → 人话"
OUT=$("$BUILD/doip-dump" "02 FD 80 01 00 00 00 07 0E 00 00 01 22 F1 90" 2>&1)
echo "$OUT" | grep -q "0x8001"               && ok "doip-dump 认出 0x8001"          || bad "doip-dump 没认出 0x8001"
echo "$OUT" | grep -q "ReadDataByIdentifier" && ok "doip-dump 认出 0x22 读 DID 服务" || bad "doip-dump 没认出 0x22"
echo "$OUT" | grep -q "0x0E00"               && ok "doip-dump 认出源地址 0x0E00"     || bad "doip-dump 没认出源地址"

step "6/7 端到端：实体 + 客户端走真 UDP（loopback，端口 13455）"
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

step "7/7 端到端：实体 + 客户端走真 TCP（loopback，端口 13456）"
# 心跳周期调到 5000ms：这条用例要的是"能激活、心跳能一问一答"，
# 不让服务器主动发心跳来抢戏（那条逻辑由 routing-selftest 用 150ms 单独测）。
"$BUILD/doip-serve" --port 13456 --seconds 3 --idle-ms 5000 > "$LOG/tcpserve.log" 2>&1 &
TCP=$!
sleep 0.4
if "$BUILD/doip-client" --host 127.0.0.1 --port 13456 --sa 0E00 --alive > "$LOG/tcpclient.log" 2>&1; then
    ok "客户端走完 连接→激活→心跳"
else
    bad "客户端 TCP 流程失败"
    cat "$LOG/tcpclient.log" | sed 's/^/      /'
fi
wait $TCP || true
grep -q "code=0x10"      "$LOG/tcpclient.log" && ok "0x0006 应答码 0x10（激活成功）" || bad "应答码不是 0x10"
grep -q "0x0008 心跳应答" "$LOG/tcpclient.log" && ok "0x0007 问到了 0x0008"           || bad "心跳没应答"
grep -q "成功激活 1 次"    "$LOG/tcpserve.log"  && ok "实体侧确认激活 1 次"             || bad "实体侧没记录到激活"
echo "      --- 客户端看到 ---"
head -5 "$LOG/tcpclient.log" | sed 's/^/      /'

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] && echo "本地这条腿全绿。" && exit 0
echo "先修红的，再推 Git。"
exit 1
