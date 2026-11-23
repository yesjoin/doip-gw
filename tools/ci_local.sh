#!/usr/bin/env bash
# ============================================================================
# ci_local.sh —— 在本地把 CI 的每一步原样跑一遍（M0 版）
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

step "1/5 编译器"
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

step "2/5 配置（干净目录，等价于 CI 全新克隆）"
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

step "3/5 构建 -Wall -Wextra -Wpedantic $([ "$WERROR" -eq 1 ] && echo '+ -Werror')"
if cmake --build "$BUILD" -j"$(nproc)" > "$LOG/build.log" 2>&1; then
    ok "构建成功"
else
    bad "构建失败"
    grep -m 10 -E "error:|Error " "$LOG/build.log" | sed 's/^/      /'
fi
W=$(grep -c "warning:" "$LOG/build.log" 2>/dev/null) || W=0
[ "$W" -eq 0 ] && ok "零编译警告" || echo "[WARN] 有 $W 条编译警告"

step "4/5 自测（ctest）"
if (cd "$BUILD" && ctest --output-on-failure > "$LOG/ctest.log" 2>&1); then
    ok "ctest 全绿"
else
    bad "ctest 有失败"
    tail -n 30 "$LOG/ctest.log" | sed 's/^/      /'
fi
echo "      用例明细："
grep -E "^ *[0-9]+/[0-9]+ Test" "$LOG/ctest.log" | sed 's/^/      /' || true

step "5/5 工具冒烟：十六进制 → 人话"
OUT=$("$BUILD/doip-dump" "02 FD 80 01 00 00 00 07 0E 00 00 01 22 F1 90" 2>&1)
echo "$OUT" | grep -q "0x8001"               && ok "doip-dump 认出 0x8001"          || bad "doip-dump 没认出 0x8001"
echo "$OUT" | grep -q "ReadDataByIdentifier" && ok "doip-dump 认出 0x22 读 DID 服务" || bad "doip-dump 没认出 0x22"
echo "$OUT" | grep -q "0x0E00"               && ok "doip-dump 认出源地址 0x0E00"     || bad "doip-dump 没认出源地址"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] && echo "本地这条腿全绿。" && exit 0
echo "先修红的，再推 Git。"
exit 1
