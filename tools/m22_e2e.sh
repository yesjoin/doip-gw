#!/usr/bin/env bash
# =============================================================================
# m22_e2e.sh —— M22 验收：钥匙表（读表 / 装钥匙 / 退役 / 吊销）
#
# 用法： bash tools/m22_e2e.sh [端口A] [端口B]      默认 13487 / 13488
#
# 这一步要立住的判据：
#   · 钥匙从"源码里写死"变成"表里的一行"：装、退役、吊销、读表都能在总线上做；
#   · 退役 ≠ 吊销：退役的钥匙**还能验**已经签好的包（在途包不能突然判死），
#     吊销的钥匙立刻拒收，而且是**终态**（要恢复只能装新 keyId）；
#   · 同 id 不许覆盖安装：覆盖等于让知道旧钥匙的人换掉 Active 槽位；
#   · 装钥匙要过门（编程会话 + 解锁），但**读表**不用 —— 问和做的分工，M20 立的规矩继续用。
#
# 腿一：默认表 1/2 启用，刷写 + 门禁开着（装 3 → 退役 → 切回 → 退役 1 → 验 → 吊销 1 → 拒）。
# 腿二：启动就 --revoke-key 1（泄露的那把吊死，1 号签的包直接拒，2 号照验）。
# =============================================================================
set -u

PORT_A=${1:-13487}
PORT_B=${2:-13488}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m22_check.py
ELOG=/tmp/m22_ecu.log
SLOG=/tmp/m22_gw.log
OUT=/tmp/m22_check.txt

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
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m22_check.py 自身编译不过（先 py_compile）"; exit 1; }

cleanup
echo "=== 1 腿一：默认表 1/2 启用，--require-compat，门禁开着 ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 26 \
        --flash --flash-block 34 --flash-max 65536 --secure --require-compat > "$ELOG" 2>&1 &
STUB1_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT_A" --seconds 24 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

# M24 给 banner 加了摘要与容量表决两行，所以这里只认"三个服务的名字"——不认整句措辞。
# （读表 / 装钥匙 / 改状态 三个都在；整句会随新服务增加而变，拿整句当接口就得每次跟着改）
grep -q "钥匙：0x22 F1B0 读表" "$ELOG" && grep -q "0x31 01 02 06" "$ELOG" && grep -q "0x31 01 02 07" "$ELOG" \
    && ok "启动行说清了读表 / 装钥匙 / 改状态三个服务" || bad "启动行没提钥匙服务"

echo
echo "=== 2 腿一场景（读表 → 装 3 → 不许覆盖 → 退役/启用 → 退役 1 照验 → 吊销 1 拒收 → 终态 → 复位后门禁） ==="
python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿一脚本自身 0 失败" || bad "腿一脚本里有失败项"

# 注意：读表的值本身就带 "="（0001=00），所以只能切第一段：cut -d= -f2-
grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2-; }

[ "$(grab ACT_CODE)" = "10" ] && ok "路由激活 0x10" || bad "ACT_CODE=$(grab ACT_CODE)"
[ "$(grab CAR_PART)" = "PART-ABC1234" ] && ok "车报的零件号" || bad "CAR_PART=$(grab CAR_PART)"
[ "$(grab TABLE_BOOT)" = "0001=00,0002=00" ] && ok "0x22 F1B0 读出默认表：两把都启用" || bad "TABLE_BOOT=$(grab TABLE_BOOT)"
[ "$(grab UNLOCK)" = "OK" ] && ok "解锁" || bad "UNLOCK=$(grab UNLOCK)"
[ "$(grab INSTALL_3)" = "7101020600" ] && ok "0206 装上 3 号钥匙 → 00" || bad "INSTALL_3=$(grab INSTALL_3)"
[ "$(grab TABLE_AFTER_INSTALL)" = "0001=00,0002=00,0003=00" ] && ok "装完表里多一把（0003 启用）" || bad "TABLE_AFTER_INSTALL=$(grab TABLE_AFTER_INSTALL)"
[ "$(grab INSTALL_DUP)" = "7101020601" ] && ok "同一个 id 再装 → 01（不许覆盖）" || bad "INSTALL_DUP=$(grab INSTALL_DUP)"
[ "$(grab NRC_INSTALL_LEN)" = "7F3113" ] && ok "材料只有 31 字节 → 7F 31 13" || bad "NRC_INSTALL_LEN=$(grab NRC_INSTALL_LEN)"
[ "$(grab INSTALL_ZERO_ID)" = "7101020601" ] && ok "keyId 0 → 01（0 是「没有钥匙」，不能占槽）" || bad "INSTALL_ZERO_ID=$(grab INSTALL_ZERO_ID)"
[ "$(grab RETIRE_3)" = "7101020700" ] && ok "0207 把 3 号退役 → 00" || bad "RETIRE_3=$(grab RETIRE_3)"
[ "$(grab TABLE_RETIRED_3)" = "0001=00,0002=00,0003=01" ] && ok "读表看到 0003=01（退役）" || bad "TABLE_RETIRED_3=$(grab TABLE_RETIRED_3)"
[ "$(grab REVIVE_3)" = "7101020700" ] && ok "退役切回启用 → 00（回滚是合法操作）" || bad "REVIVE_3=$(grab REVIVE_3)"
[ "$(grab TABLE_REVIVED_3)" = "0001=00,0002=00,0003=00" ] && ok "读表回到 0003=00" || bad "TABLE_REVIVED_3=$(grab TABLE_REVIVED_3)"
[ "$(grab STATE_BAD)" = "7F3131" ] && ok "目标状态 03 → 7F 31 31（只认 00/01/02）" || bad "STATE_BAD=$(grab STATE_BAD)"
[ "$(grab STATE_MISSING)" = "7101020701" ] && ok "表里没有 9 号 → 01" || bad "STATE_MISSING=$(grab STATE_MISSING)"
[ "$(grab RETIRE_1)" = "7101020700" ] && ok "把 1 号（老钥匙）退役 → 00" || bad "RETIRE_1=$(grab RETIRE_1)"
[ "$(grab ERASE_1)" = "7101FF00" ] && ok "擦除（为推镜像做准备）" || bad "ERASE_1=$(grab ERASE_1)"
[ "$(grab PRECHECK_3)" = "7101020500" ] && ok "用 3 号签的 v2 包预检 → 00（新钥匙能用）" || bad "PRECHECK_3=$(grab PRECHECK_3)"
[ "$(grab DOWNLOAD)" = "74200022" ] && ok "持预检凭证 0x34 放行" || bad "DOWNLOAD=$(grab DOWNLOAD)"
[ "$(grab BLOCK_1)" = "7601" ] && ok "0x36 收块" || bad "BLOCK_1=$(grab BLOCK_1)"
IMG_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*29+5)&0xFF for i in range(8)])) & 0xFFFFFFFF))')
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ] && ok "0x37 的 CRC 是 $IMG_CRC" || bad "EXIT_CRC=$(grab EXIT_CRC)"
[ "$(grab VERIFY_RETIRED_KEY)" = "7101FF0200" ] && ok "**退役钥匙签的包照验**（00，在途包不能突然判死）" || bad "VERIFY_RETIRED_KEY=$(grab VERIFY_RETIRED_KEY)"
[ "$(grab REVOKE_1)" = "7101020700" ] && ok "把 1 号吊销 → 00" || bad "REVOKE_1=$(grab REVOKE_1)"
[ "$(grab VERIFY_REVOKED_KEY)" = "7F3131" ] && ok "**吊销钥匙签的包立刻被拒**（7F 31 31）" || bad "VERIFY_REVOKED_KEY=$(grab VERIFY_REVOKED_KEY)"
[ "$(grab REVIVE_REVOKED)" = "7101020701" ] && ok "想把吊销的钥匙切回启用 → 01（终态出不去）" || bad "REVIVE_REVOKED=$(grab REVIVE_REVOKED)"
[ "$(grab VERIFY_NEW_KEY)" = "7101FF0200" ] && ok "3 号签的 v2 包 → 00（轮换之后新钥匙顶上）" || bad "VERIFY_NEW_KEY=$(grab VERIFY_NEW_KEY)"
[ "$(grab RESET_HARD)" = "5101" ] && ok "硬复位（回到默认会话）" || bad "RESET_HARD=$(grab RESET_HARD)"
[ "$(grab INSTALL_GATE)" = "7F317F" ] && ok "默认会话里装钥匙 → 7F 31 7F（动作要过门）" || bad "INSTALL_GATE=$(grab INSTALL_GATE)"
[ "$(grab TABLE_AFTER_RESET)" = "0001=02,0002=00,0003=00" ] && ok "**默认会话里读表照样能读**（问不用过门）" || bad "TABLE_AFTER_RESET=$(grab TABLE_AFTER_RESET)"
[ "$(grab UNLOCK_2)" = "OK" ] && ok "重新解锁" || bad "UNLOCK_2=$(grab UNLOCK_2)"
[ "$(grab INSTALL_AFTER_UNLOCK)" = "7101020600" ] && ok "解锁后同一件事就能做（0004 装上）" || bad "INSTALL_AFTER_UNLOCK=$(grab INSTALL_AFTER_UNLOCK)"

echo
echo "=== 3 等腿一 ECU 退场，核对日志与账 ==="
wait "$STUB1_PID" 2>/dev/null
grep -q "装上新钥匙 0x0004（启用）" "$ELOG" \
    && ok "日志把「装上了」和装完的表一起写出来" || bad "日志里没有装钥匙说明"
grep -q "退役钥匙 0x0001，照验" "$ELOG" \
    && ok "退役钥匙验过时日志点名「退役钥匙，照验」（审计要看这个）" || bad "日志里没有退役钥匙说明"
grep -q "已被吊销（这把钥匙不可信，拒收它签的一切）" "$ELOG" \
    && ok "吊销钥匙的拒绝理由写在日志里（31 只有结论）" || bad "日志里没有吊销拒绝"
grep -q "已吊销，终态出不去" "$ELOG" \
    && ok "想把吊销的钥匙复活时，日志解释了为什么不行" || bad "日志里没有终态说明"
line=$(grep -o "钥匙：安装 [0-9]* 次（成 [0-9]* / 拒 [0-9]*），状态变更 [0-9]* 次；退役钥匙验签 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "安装 4 次" && ok "账：装钥匙 4 次（3 号 / 重复 3 号 / 0 号 / 4 号）" || bad "安装次数对不上（$line）"
echo "$line" | grep -q "成 2 / 拒 2" && ok "账：成 2 / 拒 2" || bad "成败对不上（$line）"
echo "$line" | grep -q "状态变更 4 次" && ok "账：状态变更 4 次（退役 3 / 启用 3 / 退役 1 / 吊销 1）" || bad "状态变更对不上（$line）"
echo "$line" | grep -q "退役钥匙验签 1 次" && ok "账：退役钥匙验签 1 次" || bad "退役验签对不上（$line）"

echo
echo "=== 4 腿二：启动就 --revoke-key 1（泄露的那把吊死） ==="
cleanup
: > "$ELOG"
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 14 \
        --flash --flash-block 34 --flash-max 65536 --secure --require-compat \
        --revoke-key 1 > "$ELOG" 2>&1 &
STUB2_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT_B" --seconds 12 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿二脚本自身 0 失败" || bad "腿二脚本里有失败项"

[ "$(grab TABLE_BOOT_REVOKED)" = "0001=02,0002=00" ] && ok "启动表里 1 号直接是吊销态（02）" || bad "TABLE_BOOT_REVOKED=$(grab TABLE_BOOT_REVOKED)"
[ "$(grab PRECHECK_BOOT_REVOKED)" = "7F3131" ] && ok "1 号签的 v2 包预检被拒（7F 31 31）" || bad "PRECHECK_BOOT_REVOKED=$(grab PRECHECK_BOOT_REVOKED)"
[ "$(grab PRECHECK_BOOT_OK)" = "7101020500" ] && ok "2 号签的包照验（00）—— 吊销只影响那一把" || bad "PRECHECK_BOOT_OK=$(grab PRECHECK_BOOT_OK)"

echo
echo "=== 5 等腿二 ECU 退场 ==="
wait "$STUB2_PID" 2>/dev/null
grep -q "keyId 0x0001 已被吊销" "$ELOG" \
    && ok "腿二日志点名「0x0001 已被吊销」" || bad "腿二日志里没有吊销拒绝"
line=$(grep -o "钥匙：安装 [0-9]* 次（成 [0-9]* / 拒 [0-9]*），状态变更 [0-9]* 次；退役钥匙验签 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "状态变更 0 次" && ok "账：腿二没改过状态（吊销是启动参数给的）" || bad "状态变更对不上（$line）"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M22 全绿 —— 钥匙是一张活的表：能装、能退役（照验）、能吊销（拒收且不可复活）；装钥匙过门，读表不用。"
    exit 0
fi
exit 1
