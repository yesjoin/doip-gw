#!/usr/bin/env bash
# =============================================================================
# m24_e2e.sh —— M24 验收：车队钥匙清单（广播表决 + 逐台下发 + 摘要核对）
#
# 用法： bash tools/m24_e2e.sh [端口A] [端口B]      默认 13491 / 13492
#
# 这一步要立住的判据：
#   · 功能寻址的请求必须是单帧（7 字节）→ **广播搬不动 38 字节的"装钥匙"**，
#     网关应该直接 0x8003 / 0x04，而不是悄悄分段；
#   · 所以车队顺序是：广播问容量（020A）→ 逐台下发（0206）→ 广播摘要（F1B1）核对；
#   · 摘要压成 4 个计数（总/启/退/吊）刚好 7 字节 —— 它能广播，而 3+3N 的全表不能；
#   · 表决通过 ≠ 装成功：020A 只看容量，门在 0206 上各自还要过一遍；
#   · 部分成功必须被点名：哪台装不上、哪台的摘要跟别人不一样。
#
# 腿一：三台健康 ECU —— 摘要一致 → 表决能装 → 广播装钥匙被拒 → 逐台装 → 摘要变化 → 退役一台即不一致 → 补齐 → 全部吊销。
# 腿二：沿用腿一的表，把 0x0006 的表文件写坏 —— 表决 2 对 1 错 → 逐台装 2 成 1 拒 → 摘要不一致并点名 0006。
# =============================================================================
set -u

PORT_A=${1:-13491}
PORT_B=${2:-13492}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m24_check.py
STORE_A=/tmp/m24_keys_a.txt     # 0x0003
STORE_B=/tmp/m24_keys_b.txt     # 0x0006
STORE_C=/tmp/m24_keys_c.txt     # 0x0007
ELOG_A=/tmp/m24_ecu_a.log
ELOG_B=/tmp/m24_ecu_b.log
ELOG_C=/tmp/m24_ecu_c.log
SLOG=/tmp/m24_gw.log
OUT=/tmp/m24_check.txt

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
    pkill -x doip-gateway 2>/dev/null || true
    pkill -x stub-ecu 2>/dev/null || true
    true
}
trap cleanup EXIT

[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB"; exit 0; }
command -v python3 >/dev/null 2>&1 || { skip "没有 python3"; exit 0; }
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m24_check.py 自身编译不过（先 py_compile）"; exit 1; }

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2-; }

start_fleet() {   # $1=端口 $2=秒数
    local port=$1 secs=$2
    cleanup
    : > "$ELOG_A"; : > "$ELOG_B"; : > "$ELOG_C"
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 --func-rx 7DF \
            --vin LSVZZ0000B7654321 --hw HW02 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure \
            --key-store "$STORE_A" > "$ELOG_A" 2>&1 &
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 18DA00F1 --tx 18DAF100 --func-rx 7DF \
            --vin LSVCC0000C7654321 --hw HW03 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure \
            --key-store "$STORE_B" > "$ELOG_B" 2>&1 &
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 7B0 --tx 7B8 --func-rx 7DF \
            --vin LSVBB0000B7654321 --hw HW04 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure \
            --key-store "$STORE_C" > "$ELOG_C" 2>&1 &
    stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
            --route 0003:7A0:7A8:ECU_A \
            --route 0006:18DA00F1:18DAF100:ECU_B \
            --route 0007:7B0:7B8:ECU_C \
            --func 0xE400:0x7DF:ALL > "$SLOG" 2>&1 &
    sleep 1.5
}

# =============================================================================
echo "=== 1 腿一：三台健康 ECU —— 摘要一致、表决能装、广播装钥匙被拒 ==="
cleanup
rm -f "$STORE_A" "$STORE_B" "$STORE_C" "$STORE_A.tmp" "$STORE_B.tmp" "$STORE_C.tmp"
start_fleet "$PORT_A" 24

grep -q "TA=0xE400 → 0x7DF" "$SLOG" && ok "网关的功能路由打出来了（0xE400 → 7DF）" || bad "网关没有功能路由"
[ -f "$STORE_A" ] && [ -f "$STORE_B" ] && [ -f "$STORE_C" ] \
    && ok "三台各自建了自己的表文件（不是共享一张）" || bad "三台的表文件没建全"

python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿一脚本自身 0 失败" || bad "腿一有失败项"

[ "$(grab BC_DIGEST_COUNT)" = "3" ] && ok "广播摘要 F1B1 三台都答（7 字节塞得进单帧）" || bad "BC_DIGEST_COUNT=$(grab BC_DIGEST_COUNT)"
[ "$(grab BC_DIGEST_BOOT)" = "0003=62F1B102020000,0006=62F1B102020000,0007=62F1B102020000" ] \
    && ok "三台摘要一致：2/2/0/0（总 2、启用 2）" || bad "BC_DIGEST_BOOT=$(grab BC_DIGEST_BOOT)"

case "$(grab BC_INSTALL_NACK)" in
    *04) ok "广播装钥匙被网关拒 0x8003/0x04（38 字节不是单帧，不悄悄分段）" ;;
    *)   bad "BC_INSTALL_NACK=$(grab BC_INSTALL_NACK)" ;;
esac
[ "$(grab BC_INSTALL_REPLIES)" = "0" ] && ok "被拒的广播一条 ECU 应答都没有（请求根本没上总线）" || bad "BC_INSTALL_REPLIES=$(grab BC_INSTALL_REPLIES)"

[ "$(grab BC_CAP)" = "0003=7101020A00,0006=7101020A00,0007=7101020A00" ] \
    && ok "广播表决 020A：三台都「能装」" || bad "BC_CAP=$(grab BC_CAP)"
[ "$(grab TABLES_BOOT)" = "0003:0001=00,0002=00;0006:0001=00,0002=00;0007:0001=00,0002=00" ] \
    && ok "逐台读全表：三台都是默认两把" || bad "TABLES_BOOT=$(grab TABLES_BOOT)"

[ "$(grab PHYS_INSTALL_3)" = "三台都 00" ] && ok "逐台下发 0206：三台都装上 3 号" || bad "PHYS_INSTALL_3=$(grab PHYS_INSTALL_3)"
[ "$(grab DIGEST_AFTER_INSTALL)" = "0003:3/3/0/0;0006:3/3/0/0;0007:3/3/0/0" ] \
    && ok "摘要跟着变成 3/3/0/0（不用读全表也能看到变化）" || bad "DIGEST_AFTER_INSTALL=$(grab DIGEST_AFTER_INSTALL)"

[ "$(grab DIGEST_SPLIT)" = "0003:3/2/1/0;0006:3/3/0/0;0007:3/3/0/0" ] \
    && ok "只退役一台：摘要立刻分叉（3/2/1/0 vs 3/3/0/0）" || bad "DIGEST_SPLIT=$(grab DIGEST_SPLIT)"
[ "$(grab DIGEST_AGAIN)" = "0003:3/2/1/0;0006:3/2/1/0;0007:3/2/1/0" ] \
    && ok "补齐另外两台后摘要回到一致" || bad "DIGEST_AGAIN=$(grab DIGEST_AGAIN)"
[ "$(grab DIGEST_FINAL)" = "0003:3/1/1/1;0006:3/1/1/1;0007:3/1/1/1" ] \
    && ok "三台一起吊销 1 号：3/1/1/1（总 3、启用 1、退役 1、吊销 1）" || bad "DIGEST_FINAL=$(grab DIGEST_FINAL)"

wait 2>/dev/null
grep -q "钥匙摘要：共 3 / 启用 3" "$ELOG_B" && ok "0x0006 日志记了摘要（每台各记各的账）" || bad "0x0006 日志没有摘要"
grep -q "广播" "$ELOG_A" && ok "ECU 日志标出广播来的请求" || bad "ECU 日志没标广播"

# =============================================================================
echo
echo "=== 2 腿二：0x0006 的表文件写坏 —— 表决 2 对 1 错，装完摘要分叉 ==="
python3 - "$STORE_B" <<'PY'
import sys
p = sys.argv[1]
with open(p, "rb") as f:
    data = f.read()
with open(p, "wb") as f:
    f.write(data[:-10])          # 模拟写到一半断电
print("写坏了 %s：%d → %d 字节" % (p, len(data), len(data) - 10))
PY

start_fleet "$PORT_B" 20
grep -q "文件坏了，不采用" "$ELOG_B" && ok "0x0006 启动判 Corrupt（表空、不许写）" || bad "0x0006 没有判 Corrupt"

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿二脚本自身 0 失败" || bad "腿二有失败项"

[ "$(grab BC_CAP_PARTIAL)" = "0003=7101020A00,0006=7101020A02,0007=7101020A00" ] \
    && ok "广播表决：两台 00、坏的那台 02（表坏，别下发）" || bad "BC_CAP_PARTIAL=$(grab BC_CAP_PARTIAL)"
[ "$(grab PHYS_INSTALL_4_PARTIAL)" = "0003=7101020600,0006=7F3122,0007=7101020600" ] \
    && ok "逐台下发 4 号：两台 00、坏台 7F 31 22" || bad "PHYS_INSTALL_4_PARTIAL=$(grab PHYS_INSTALL_4_PARTIAL)"
[ "$(grab BC_SUMMARY)" = "成 2 / 拒 1" ] \
    && ok "汇总如实报「成 2 / 拒 1」—— 车队操作没有事务，只能收齐再算" || bad "BC_SUMMARY=$(grab BC_SUMMARY)"
[ "$(grab DIGEST_PARTIAL)" = "0003:4/2/1/1;0006:0/0/0/0;0007:4/2/1/1" ] \
    && ok "摘要：两台 4/2/1/1，坏台 0/0/0/0" || bad "DIGEST_PARTIAL=$(grab DIGEST_PARTIAL)"
[ "$(grab FLEET_CONSISTENT)" = "不一致，0006 的摘要与 0x0003 不同" ] \
    && ok "一致性核对**点名** 0006（不能只说「不一致」）" || bad "FLEET_CONSISTENT=$(grab FLEET_CONSISTENT)"

wait 2>/dev/null
grep -q "钥匙表文件是坏的" "$ELOG_B" && ok "坏台的日志把理由写清楚了（为什么回 22）" || bad "坏台日志没有理由"

cleanup
rm -f "$STORE_A" "$STORE_B" "$STORE_C" "$STORE_A.tmp" "$STORE_B.tmp" "$STORE_C.tmp"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M24 全绿 —— 广播只能投票（020A）、搬数据要逐台（0206）、核对靠摘要（F1B1）；部分成功必须点名。"
    exit 0
fi
exit 1
