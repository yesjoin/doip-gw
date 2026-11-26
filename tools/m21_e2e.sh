#!/usr/bin/env bash
# =============================================================================
# m21_e2e.sh —— M21 验收：包自己带身份（0x31 01 0205 预检 + FF02 身份核对）
#
# 用法： bash tools/m21_e2e.sh [端口A] [端口B]      默认 13485 / 13486
#
# 这一步要立住的判据：
#   · 身份写进清单、又落在标签覆盖范围里 —— 改一个字符标签就崩，tester"说不了谎"；
#   · 0205 只收 v2（76 字节的 v1 没有身份，建立不了"已比对"的凭证）；
#   · 预检通过 → 直接发凭证（0x34 一次一用）；后一条包不通过，前一条的通过就作废；
#   · FF02 整包验签把两件事分开：包是真的（00）/ 包真但不是给这台车的（**02**）；
#   · 预检不看镜像，所以硬复位清空镜像之后照样能预检。
#
# 腿一：车 PART-ABC1234 / SW-1.0.3，--require-compat，不许降级。
# 腿二：车 SW-1.9.0，--allow-downgrade（版本按数值比）。
# =============================================================================
set -u

PORT_A=${1:-13485}
PORT_B=${2:-13486}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m21_check.py
ELOG=/tmp/m21_ecu.log
SLOG=/tmp/m21_gw.log
OUT=/tmp/m21_check.txt

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
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m21_check.py 自身编译不过（先 py_compile）"; exit 1; }

cleanup
echo "=== 1 腿一：车 SW-1.0.3，--require-compat，不许降级 ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 24 \
        --flash --flash-block 34 --flash-max 65536 --secure --require-compat > "$ELOG" 2>&1 &
STUB1_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT_A" --seconds 22 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "清单：v1 76 字节（无身份" "$ELOG" \
    && ok "启动行说清了两种清单：v1 无身份 / v2 含身份，0205 只收 v2" || bad "启动行没提清单格式"

echo
echo "=== 2 腿一场景（v1 / 长度 / 配对 / 标签 / 身份不符 / 旧凭证作废 / 真下载 / FF02 三态 / 复位后预检） ==="
python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿一脚本自身 0 失败" || bad "腿一脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab ACT_CODE)" = "10" ] && ok "路由激活 0x10" || bad "ACT_CODE=$(grab ACT_CODE)"
[ "$(grab CAR_PART)" = "PART-ABC1234" ] && ok "车报的零件号" || bad "CAR_PART=$(grab CAR_PART)"
[ "$(grab CAR_SW)" = "SW-1.0.3" ] && ok "车报的版本是 SW-1.0.3" || bad "CAR_SW=$(grab CAR_SW)"
[ "$(grab UNLOCK)" = "OK" ] && ok "解锁" || bad "UNLOCK=$(grab UNLOCK)"
[ "$(grab NRC_V1)" = "7F3131" ] && ok "0205 发 v1（76 字节）→ 7F 31 31（只收带身份的 v2）" || bad "NRC_V1=$(grab NRC_V1)"
[ "$(grab NRC_VERSION)" = "7F3131" ] && ok "104 字节却写版本 1 → 7F 31 31（长度与版本必须成对）" || bad "NRC_VERSION=$(grab NRC_VERSION)"
[ "$(grab NRC_LEN)" = "7F3113" ] && ok "清单 100 字节 → 7F 31 13（连格式都不全）" || bad "NRC_LEN=$(grab NRC_LEN)"
[ "$(grab NRC_TAG)" = "7F3131" ] && ok "用 2 号钥匙盖章、keyId 写 1 号 → 7F 31 31（标签不符）" || bad "NRC_TAG=$(grab NRC_TAG)"
[ "$(grab PART_MISMATCH)" = "7101020501" ] && ok "包里零件号是别人的 → 正响应 01（包不对，不是请求错）" || bad "PART_MISMATCH=$(grab PART_MISMATCH)"
[ "$(grab NRC_AFTER_PART_FAIL)" = "7F3422" ] && ok "身份不符的预检不成立凭证 → 0x34 回 22" || bad "NRC_AFTER_PART_FAIL=$(grab NRC_AFTER_PART_FAIL)"
[ "$(grab DOWNGRADE)" = "7101020501" ] && ok "包里版本 1.0.2 比车上 1.0.3 低 → 01（降级）" || bad "DOWNGRADE=$(grab DOWNGRADE)"
[ "$(grab PRECHECK_OK)" = "7101020500" ] && ok "包里 1.0.4 是升级 → 00" || bad "PRECHECK_OK=$(grab PRECHECK_OK)"
[ "$(grab PRECHECK_AFTER_OK_FAIL)" = "7101020501" ] && ok "紧接着换一个别人的包 → 01" || bad "PRECHECK_AFTER_OK_FAIL=$(grab PRECHECK_AFTER_OK_FAIL)"
[ "$(grab NRC_STALE_CREDENTIAL)" = "7F3422" ] && ok "上一条包的通过不能给下一条包用（旧凭证已作废 → 22）" || bad "NRC_STALE_CREDENTIAL=$(grab NRC_STALE_CREDENTIAL)"
[ "$(grab ERASE_1)" = "7101FF00" ] && ok "擦除（0x34 要求先擦过）" || bad "ERASE_1=$(grab ERASE_1)"
[ "$(grab PRECHECK_OK_2)" = "7101020500" ] && ok "擦除后重新预检通过（00）" || bad "PRECHECK_OK_2=$(grab PRECHECK_OK_2)"
[ "$(grab DOWNLOAD)" = "74200022" ] && ok "拿着预检的凭证 0x34 放行" || bad "DOWNLOAD=$(grab DOWNLOAD)"
[ "$(grab BLOCK_1)" = "7601" ] && ok "0x36 收块" || bad "BLOCK_1=$(grab BLOCK_1)"
IMG_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*29+5)&0xFF for i in range(8)])) & 0xFFFFFFFF))')
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ] && ok "0x37 的 CRC 是 $IMG_CRC" || bad "EXIT_CRC=$(grab EXIT_CRC)"
[ "$(grab VERIFY_V2_OK)" = "7101FF0200" ] && ok "FF02 + v2 清单，镜像与身份都对 → 00" || bad "VERIFY_V2_OK=$(grab VERIFY_V2_OK)"
[ "$(grab VERIFY_V2_ID_MISMATCH)" = "7101FF0202" ] && ok "FF02 + v2 清单，包真但零件号是别人的 → **02**" || bad "VERIFY_V2_ID_MISMATCH=$(grab VERIFY_V2_ID_MISMATCH)"
[ "$(grab VERIFY_V1_OK)" = "7101FF0200" ] && ok "FF02 + v1 清单照旧能用（只是没有身份）" || bad "VERIFY_V1_OK=$(grab VERIFY_V1_OK)"
[ "$(grab RESET_HARD)" = "5101" ] && ok "硬复位（镜像清空）" || bad "RESET_HARD=$(grab RESET_HARD)"
[ "$(grab UNLOCK_2)" = "OK" ] && ok "复位后重新解锁" || bad "UNLOCK_2=$(grab UNLOCK_2)"
[ "$(grab PRECHECK_AFTER_RESET)" = "7101020500" ] && ok "没有镜像也能预检（0205 只看信封，不看镜像）" || bad "PRECHECK_AFTER_RESET=$(grab PRECHECK_AFTER_RESET)"

echo
echo "=== 3 等腿一 ECU 退场，核对日志与账 ==="
wait "$STUB1_PID" 2>/dev/null
grep -q "0205 只收带身份的 v2 清单（104 字节），收到的是 v1（76 字节）" "$ELOG" \
    && ok "日志把「只收 v2」的理由写在拒绝里" || bad "日志里没有 v1 被拒的说明"
grep -q "清单版本 1 与长度 104 不配对" "$ELOG" \
    && ok "日志写清了长度与版本不配对（不是泛泛的 magic 错）" || bad "日志里没有配对错误"
grep -q "标签不符：这包不是知道钥匙的人做的" "$ELOG" \
    && ok "标签不符时日志说明「不是知道钥匙的人做的」" || bad "日志里没有标签说明"
grep -q "验签：包是真的，但不是给这台车的" "$ELOG" \
    && ok "FF02 身份不符时，日志把「包是真的」和「不是这台车的」分开说" || bad "日志里没有身份不符说明"
grep -q "v1 清单没有身份字段，兼容性还得靠 0204/0205" "$ELOG" \
    && ok "v1 通过时日志补一句「兼容性还得靠 0204/0205」（不假装它验了身份）" || bad "日志里没有 v1 身份缺口的说明"
line=$(grep -o "预检：v2 清单 [0-9]* 次 → 通过 [0-9]* 次 / 不通过 [0-9]* 次；整包验签时身份不符 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "v2 清单 9 次" && ok "账：v2 预检 9 次（v1 那次不入账：它连格式都不是 v2）" || bad "预检次数对不上（$line）"
echo "$line" | grep -q "通过 3 次" && ok "账：通过 3 次" || bad "通过次数对不上（$line）"
echo "$line" | grep -q "不通过 6 次" && ok "账：不通过 6 次" || bad "不通过次数对不上（$line）"
echo "$line" | grep -q "身份不符 1 次" && ok "账：整包验签时身份不符 1 次" || bad "身份不符次数对不上（$line）"

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

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿二脚本自身 0 失败" || bad "腿二脚本里有失败项"

[ "$(grab CAR_SW)" = "SW-1.9.0" ] && ok "车报的版本是 SW-1.9.0" || bad "CAR_SW=$(grab CAR_SW)"
[ "$(grab ERASE_1)" = "7101FF00" ] && ok "先擦除（擦除会作废凭证，所以预检得放在它之后）" || bad "ERASE_1=$(grab ERASE_1)"
[ "$(grab PRECHECK_110)" = "7101020500" ] && ok "1.9.0 → 1.10.0 判为升级（数值比较）" || bad "PRECHECK_110=$(grab PRECHECK_110)"
[ "$(grab PRECHECK_DOWNGRADE)" = "7101020500" ] && ok "1.9.0 → 1.8.0 降级，allowDowngrade 开了就放行" || bad "PRECHECK_DOWNGRADE=$(grab PRECHECK_DOWNGRADE)"
[ "$(grab PRECHECK_BAD_VERSION)" = "7101020501" ] && ok "包里的版本写成 SW-latest → 01（包有问题，不是请求有问题）" || bad "PRECHECK_BAD_VERSION=$(grab PRECHECK_BAD_VERSION)"
[ "$(grab PRECHECK_110_2)" = "7101020500" ] && ok "再预检一次通过（00）" || bad "PRECHECK_110_2=$(grab PRECHECK_110_2)"
[ "$(grab DOWNLOAD)" = "74200022" ] && ok "持预检凭证 0x34 放行" || bad "DOWNLOAD=$(grab DOWNLOAD)"

echo
echo "=== 5 等腿二 ECU 退场 ==="
wait "$STUB2_PID" 2>/dev/null
grep -q "预检：可以刷（升级：1.9.0 → 1.10.0）" "$ELOG" \
    && ok "日志把 1.9.0 → 1.10.0 写成升级（不是降级）" || bad "日志里没有升级说明"
grep -q "allowDowngrade 已开，放行" "$ELOG" \
    && ok "降级放行时日志注明了为什么放行" || bad "日志里没有降级放行说明"
grep -q "目标版本「SW-latest」不是三段数字" "$ELOG" \
    && ok "版本号格式不对时日志点名是哪个包里的版本" || bad "日志里没有坏版本号的说明"
line=$(grep -o "预检：v2 清单 [0-9]* 次 → 通过 [0-9]* 次 / 不通过 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "v2 清单 4 次" && ok "账：腿二 4 次预检" || bad "预检次数对不上（$line）"
echo "$line" | grep -q "通过 3 次" && ok "账：腿二 3 次通过" || bad "通过次数对不上（$line）"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M21 全绿 —— 身份在标签下面，tester 说不了谎；包真 ≠ 给这台车（00 与 02 分开报）。"
    exit 0
fi
exit 1
