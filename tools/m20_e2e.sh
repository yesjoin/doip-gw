#!/usr/bin/env bash
# =============================================================================
# m20_e2e.sh —— M20 验收：包与车对不对得上（0x31 01 0204 + 0x34 凭证）
#
# 用法： bash tools/m20_e2e.sh [端口A] [端口B]      默认 13483 / 13484
#
# 这一步要立住的判据：
#   · 检查本身就是"问问题"，回正响应 01 而不是 NRC（M19 立过的规矩，这里继续）；
#   · 光"检查过"不够，0x34 要**凭证**，而且凭证**一次一用**；
#   · 凭证会被擦除 / 复位 / 换会话 / 收尾作废 —— "上周检查通过"不能刷今天的包；
#   · 版本按数值比："1.10.0" 比 "1.9.0" 新（字符串比较会说反）。
#
# 腿一：车 SW-1.0.3，不许降级。腿二：车 SW-1.9.0，allowDowngrade 开。
# =============================================================================
set -u

PORT_A=${1:-13483}
PORT_B=${2:-13484}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m20_check.py
ELOG=/tmp/m20_ecu.log
SLOG=/tmp/m20_gw.log
OUT=/tmp/m20_check.txt

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    true
}
trap cleanup EXIT

[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB"; exit 0; }
command -v python3 >/dev/null 2>&1 || { skip "没有 python3"; exit 0; }
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m20_check.py 自身编译不过（先 py_compile）"; exit 1; }

cleanup
echo "=== 1 腿一：车 SW-1.0.3，--require-compat，不许降级 ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 22 \
        --flash --flash-block 34 --flash-max 65536 --secure --require-compat > "$ELOG" 2>&1 &
STUB1_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT_A" --seconds 20 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "兼容：0x31 01 0204 报「零件号 + 目标版本」" "$ELOG" \
    && ok "启动行说清了 0204 要什么、0x34 要凭证" || bad "启动行没提兼容性检查"

echo
echo "=== 2 腿一场景（没凭证 → 结构错 → 零件号/降级/同版本 → 凭证一次一用 → 作废） ==="
python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿一脚本自身 0 失败" || bad "腿一脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab ACT_CODE)" = "10" ] && ok "路由激活 0x10" || bad "ACT_CODE=$(grab ACT_CODE)"
[ "$(grab CAR_PART)" = "PART-ABC1234" ] && ok "车报的零件号和包里一致（先读再比）" || bad "CAR_PART=$(grab CAR_PART)"
[ "$(grab CAR_SW)" = "SW-1.0.3" ] && ok "车报的版本是 SW-1.0.3" || bad "CAR_SW=$(grab CAR_SW)"
[ "$(grab UNLOCK)" = "OK" ] && ok "解锁" || bad "UNLOCK=$(grab UNLOCK)"
[ "$(grab ERASE_1)" = "7101FF00" ] && ok "擦除（状态机允许下载）" || bad "ERASE_1=$(grab ERASE_1)"
[ "$(grab NRC_NO_CREDENTIAL)" = "7F3422" ] && ok "没做 0204 就 0x34 → 7F 34 22（没有凭证）" || bad "NRC_NO_CREDENTIAL=$(grab NRC_NO_CREDENTIAL)"
[ "$(grab NRC_LEN)" = "7F3113" ] && ok "0204 只给 11 字节 → 7F 31 13（零件号都不全）" || bad "NRC_LEN=$(grab NRC_LEN)"
[ "$(grab NRC_BAD_VERSION)" = "7F3131" ] && ok "版本号不是三段数字 → 7F 31 31（结构错）" || bad "NRC_BAD_VERSION=$(grab NRC_BAD_VERSION)"
[ "$(grab NRC_AFTER_BAD)" = "7F3422" ] && ok "结构错之后没留下凭证（0x34 仍 22）" || bad "NRC_AFTER_BAD=$(grab NRC_AFTER_BAD)"
[ "$(grab PART_MISMATCH)" = "7101020401" ] && ok "零件号不符 → 正响应 01（内容对不上，不是请求错）" || bad "PART_MISMATCH=$(grab PART_MISMATCH)"
[ "$(grab DOWNGRADE)" = "7101020401" ] && ok "降级 1.0.3 → 1.0.2 被拒（01）" || bad "DOWNGRADE=$(grab DOWNGRADE)"
[ "$(grab SAME_VERSION)" = "7101020400" ] && ok "同版本重刷放行（00，修复场景）" || bad "SAME_VERSION=$(grab SAME_VERSION)"
[ "$(grab COMPAT_OK)" = "7101020400" ] && ok "升级到 1.0.4 通过（00）" || bad "COMPAT_OK=$(grab COMPAT_OK)"
[ "$(grab DOWNLOAD)" = "74200022" ] && ok "持证 0x34 放行" || bad "DOWNLOAD=$(grab DOWNLOAD)"
[ "$(grab BLOCK_1)" = "7601" ] && ok "0x36 收块" || bad "BLOCK_1=$(grab BLOCK_1)"
IMG_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*29+5)&0xFF for i in range(8)])) & 0xFFFFFFFF))')
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ] && ok "0x37 的 CRC 是 $IMG_CRC" || bad "EXIT_CRC=$(grab EXIT_CRC)"
[ "$(grab ERASE_2)" = "7101FF00" ] && ok "第二轮擦除" || bad "ERASE_2=$(grab ERASE_2)"
[ "$(grab NRC_AFTER_EXIT)" = "7F3422" ] && ok "收尾之后凭证作废 → 再 0x34 回 22（一次一用）" || bad "NRC_AFTER_EXIT=$(grab NRC_AFTER_EXIT)"
[ "$(grab COMPAT_OK_2)" = "7101020400" ] && ok "重新检查通过" || bad "COMPAT_OK_2=$(grab COMPAT_OK_2)"
[ "$(grab ERASE_CLEARS)" = "7101FF00" ] && ok "接着擦除（擦除本身会作废凭证）" || bad "ERASE_CLEARS=$(grab ERASE_CLEARS)"
[ "$(grab NRC_AFTER_ERASE)" = "7F3422" ] && ok "擦除作废凭证 → 0x34 回 22（重刷必须重新检查）" || bad "NRC_AFTER_ERASE=$(grab NRC_AFTER_ERASE)"

echo
echo "=== 3 等腿一 ECU 退场，核对日志与账 ==="
wait "$STUB1_PID" 2>/dev/null
grep -q "零件号不符：车上 PART-ABC1234，包里 PART-XYZ9999" "$ELOG" \
    && ok "日志写清了零件号两边各是什么" || bad "日志里没有零件号差异"
grep -q "降级：车上 1.0.3，包里 1.0.2（没开 allowDowngrade）" "$ELOG" \
    && ok "日志把降级和「没开 allowDowngrade」写在了一起" || bad "日志里没有降级原因"
grep -q "同版本重刷：1.0.3" "$ELOG" \
    && ok "同版本重刷在日志里被标成修复场景" || bad "日志里没有同版本说明"
grep -q "0x34 被拒：没有有效的兼容性凭证" "$ELOG" \
    && ok "0x34 的拒绝理由落在日志里（22 只有结论）" || bad "日志里没有凭证拒绝"
line=$(grep -o "兼容：检查 [0-9]* 次 → 通过 [0-9]* 次 / 不通过 [0-9]* 次；凭证用掉 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "检查 5 次" && ok "账：检查 5 次（零件号 / 降级 / 同版本 / 两次通过）" || bad "检查次数对不上（$line）"
echo "$line" | grep -q "通过 3 次" && ok "账：通过 3 次" || bad "通过次数对不上（$line）"
echo "$line" | grep -q "不通过 2 次" && ok "账：不通过 2 次（零件号 / 降级）" || bad "不通过次数对不上（$line）"
echo "$line" | grep -q "凭证用掉 1 次" && ok "账：凭证用掉 1 次（只有那一次真下载）" || bad "凭证用掉次数对不上（$line）"

echo
echo "=== 4 腿二：车 SW-1.9.0，--allow-downgrade（版本按数值比） ==="
cleanup
: > "$ELOG"
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 16 \
        --flash --flash-block 34 --flash-max 65536 --secure --require-compat \
        --allow-downgrade --sw-version SW-1.9.0 > "$ELOG" 2>&1 &
STUB2_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT_B" --seconds 14 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "allowDowngrade 已开，可降级" "$ELOG" \
    && ok "启动行说明了「允许降级」这个开关" || bad "启动行没提 allowDowngrade"

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿二脚本自身 0 失败" || bad "腿二脚本里有失败项"

[ "$(grab CAR_SW)" = "SW-1.9.0" ] && ok "车报的版本是 SW-1.9.0" || bad "CAR_SW=$(grab CAR_SW)"
[ "$(grab STRING_TRAP)" = "1" ] && ok "对照：字符串比较确实会说 1.10.0 < 1.9.0（所以不能按字符串比）" || bad "STRING_TRAP=$(grab STRING_TRAP)"
[ "$(grab UPGRADE_110)" = "7101020400" ] && ok "1.9.0 → 1.10.0 判为**升级**，放行（数值比较生效）" || bad "UPGRADE_110=$(grab UPGRADE_110)"
[ "$(grab DOWNGRADE_ALLOWED)" = "7101020400" ] && ok "1.9.0 → 1.8.0 降级，allowDowngrade 开了就放行" || bad "DOWNGRADE_ALLOWED=$(grab DOWNGRADE_ALLOWED)"

echo
echo "=== 5 等腿二 ECU 退场 ==="
wait "$STUB2_PID" 2>/dev/null
grep -q "升级：1.9.0 → 1.10.0" "$ELOG" \
    && ok "日志把 1.9.0 → 1.10.0 写成升级（不是降级）" || bad "日志里没有升级说明"
grep -q "allowDowngrade 已开，放行" "$ELOG" \
    && ok "降级放行时日志注明了为什么放行" || bad "日志里没有降级放行说明"
line=$(grep -o "兼容：检查 [0-9]* 次 → 通过 [0-9]* 次 / 不通过 [0-9]* 次；凭证用掉 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "通过 4 次" && ok "账：腿二 4 次通过（零件号那次不通过也有账）" || bad "通过次数对不上（$line）"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M20 全绿 —— 包和车对不上就不刷；凭证一次一用，擦除/复位/换会话/收尾都会作废。"
    exit 0
fi
exit 1
