#!/usr/bin/env bash
# =============================================================================
# m17_e2e.sh —— M17 验收：0x11 ECUReset（硬 / 点火循环 / 软）× 会话门禁 × 镜像语义
#
# 用法： bash tools/m17_e2e.sh [端口]        默认 13477（第二条腿用 端口+1）
#
# M16 把门装上了，但刷完之后 ECU 还得"重启一次才算生效"——那是 0x11。
# 这一节证明复位不是"回个 51 就完事"：
#   · 默认会话里也允许复位（它就是"弄乱了以后一键复原"）；
#   · 刷到一半（0x34 之后、0x37 之前）复位 → 0x22，且不许把下载搞坏；
#   · 软复位（03）清会话/解锁，**镜像留着**（同一份 CRC 还能校验通过）；
#   · 硬复位（01）清镜像并回到"未擦除"（再 0x34 必 0x22，得重新 FF00）；
#   · 子功能错 0x12、连子功能都没有 0x13。
#
# 两条腿：
#   ① --flash --secure：复位 × 门禁（主场景）
#   ② --flash（不带 --secure）：老 ECU 上 0x11 走"不支持"兜底（7F 11 31）
#      —— 保证 M15/M16 的回归腿不会被 M17 改红。
# =============================================================================
set -u

PORT=${1:-13477}
PORT2=$((PORT + 1))
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m17_check.py
SLOG=/tmp/m17_gw.log
ELOG=/tmp/m17_ecu.log
SLOG2=/tmp/m17_gw_legacy.log
ELOG2=/tmp/m17_ecu_legacy.log
OUT=/tmp/m17_check.txt
OUT2=/tmp/m17_check_legacy.txt

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

IMG_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*29+5)&0xFF for i in range(8)])) & 0xFFFFFFFF))')

cleanup
echo "=== 1 启动：网关 + 一台带 --flash --secure 的 ECU ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 24 \
        --flash --flash-block 34 --flash-max 65536 --secure > "$ELOG" 2>&1 &
STUB_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 22 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "复位：0x11 01 硬复位（清镜像）" "$ELOG" \
    && ok "启动行把三个复位子功能与镜像语义说清楚" || bad "启动行没提复位"
grep -q "默认会话也能复位，刷写中途回 0x22" "$ELOG" \
    && ok "启动行声明两条边界（默认会话可复位 / 刷写中途拒）" || bad "启动行的复位边界不对"

echo
echo "=== 2 场景（m17_check.py：默认会话复位 → 下载中途 22 → 软复位留镜像 → 硬复位清镜像） ==="
python3 "$CHECK" "$PORT" > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "场景脚本自身 0 失败" || bad "场景脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab VIN_DEFAULT)" = "LSVZZ0000B7654321" ] \
    && ok "复位加进来，老服务照旧（22 F1 90 回 VIN）" || bad "VIN=$(grab VIN_DEFAULT)"
[ "$(grab NRC_34_DEFAULT)" = "7F" ] \
    && ok "默认会话里 0x34 仍是 0x7F（M16 的门没被 M17 拆掉）" || bad "NRC_34_DEFAULT=$(grab NRC_34_DEFAULT)"
[ "$(grab NRC_11_LEN)" = "13" ] && ok "0x11 一个字节都不带 → 0x13（长度错）" || bad "NRC_11_LEN=$(grab NRC_11_LEN)"
[ "$(grab NRC_11_SUB)" = "12" ] && ok "0x11 04 → 0x12（子功能只认 01/02/03）" || bad "NRC_11_SUB=$(grab NRC_11_SUB)"
[ "$(grab RESET_IN_DEFAULT)" = "5101" ] \
    && ok "默认会话里 0x11 01 照样接受（51 01，不是 7F）" || bad "RESET_IN_DEFAULT=$(grab RESET_IN_DEFAULT)"
[ "$(grab UNLOCK_1)" = "OK" ] && ok "进编程会话 + 解锁（第一条解锁路径）" || bad "UNLOCK_1=$(grab UNLOCK_1)"
[ "$(grab ERASE)" = "7101FF00" ] && ok "擦除 71 01 FF 00" || bad "ERASE=$(grab ERASE)"
[ "$(grab DOWNLOAD)" = "74200022" ] && ok "0x34 放行（74 20 00 22）" || bad "DOWNLOAD=$(grab DOWNLOAD)"
[ "$(grab BLOCK_1)" = "7601" ] && ok "0x36 收下第一块（76 01）" || bad "BLOCK_1=$(grab BLOCK_1)"
[ "$(grab NRC_11_BUSY)" = "22" ] \
    && ok "刷到一半（0x34 之后 0x37 之前）复位 → 22（半截镜像不许当完整镜像用）" || bad "NRC_11_BUSY=$(grab NRC_11_BUSY)"
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ] \
    && ok "被拒的复位没把下载搞坏：0x37 照样收尾，CRC=$IMG_CRC" || bad "EXIT_CRC=$(grab EXIT_CRC)（期望 $IMG_CRC）"
[ "$(grab VERIFY_OK)" = "7101FF0100" ] && ok "完整性校验通过（71 01 FF 01 00）" || bad "VERIFY_OK=$(grab VERIFY_OK)"
[ "$(grab RESET_SOFT)" = "5103" ] && ok "软复位 → 51 03" || bad "RESET_SOFT=$(grab RESET_SOFT)"
[ "$(grab NRC_34_AFTER_SOFT)" = "7F" ] \
    && ok "软复位后会话回默认（0x34 → 0x7F）" || bad "NRC_34_AFTER_SOFT=$(grab NRC_34_AFTER_SOFT)"
[ "$(grab SESSION_PROG_AGAIN)" = "5002003201F4" ] \
    && ok "软复位后还能正常进编程会话" || bad "SESSION_PROG_AGAIN=$(grab SESSION_PROG_AGAIN)"
[ "$(grab NRC_34_AFTER_SOFT_PROG)" = "33" ] \
    && ok "软复位把解锁清掉了（再进编程会话仍 0x33）" || bad "NRC_34_AFTER_SOFT_PROG=$(grab NRC_34_AFTER_SOFT_PROG)"
[ "$(grab UNLOCK_2)" = "OK" ] && ok "第二次解锁" || bad "UNLOCK_2=$(grab UNLOCK_2)"
[ "$(grab IMAGE_AFTER_SOFT)" = "7101FF0100" ] \
    && ok "软复位保住镜像（同一份 CRC 仍校验通过）" || bad "IMAGE_AFTER_SOFT=$(grab IMAGE_AFTER_SOFT)"
[ "$(grab RESET_HARD)" = "5101" ] && ok "硬复位 → 51 01" || bad "RESET_HARD=$(grab RESET_HARD)"
[ "$(grab UNLOCK_3)" = "OK" ] && ok "第三次解锁" || bad "UNLOCK_3=$(grab UNLOCK_3)"
[ "$(grab IMAGE_AFTER_HARD)" = "22" ] \
    && ok "硬复位清掉镜像（校验时无镜像 → 22，不是 01）" || bad "IMAGE_AFTER_HARD=$(grab IMAGE_AFTER_HARD)"
[ "$(grab NRC_34_AFTER_HARD)" = "22" ] \
    && ok "硬复位回到未擦除（0x34 → 22，必须重新 FF00）" || bad "NRC_34_AFTER_HARD=$(grab NRC_34_AFTER_HARD)"
[ "$(grab RESET_KEYOFF)" = "5102" ] && ok "点火循环 → 51 02" || bad "RESET_KEYOFF=$(grab RESET_KEYOFF)"

echo
echo "=== 3 等 ECU 退场，核对它的账 ==="
wait "$STUB_PID" 2>/dev/null
tail -8 "$ELOG"
grep -q "\[复位\] 硬复位（断电重启）：镜像已清" "$ELOG" \
    && ok "ECU 自己说清了：硬复位清镜像（不是悄悄清）" || bad "日志里没有硬复位清镜像那一行"
line=$(grep -o "复位：硬 [0-9]* 次 / 点火循环 [0-9]* 次 / 软 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "硬 2 次" && ok "账：硬复位 2 次（默认会话一次 + 刷完之后一次）" || bad "硬复位次数对不上（$line）"
echo "$line" | grep -q "点火循环 1 次" && ok "账：点火循环 1 次" || bad "点火循环次数对不上"
echo "$line" | grep -q "软 1 次" && ok "账：软复位 1 次" || bad "软复位次数对不上"
grep -q "收下 1 块，镜像 0 字节" "$ELOG" \
    && ok "刷写账对得上：收过 1 块，但硬复位后镜像 0 字节" || bad "刷写账不对（$(grep -o '收下 .*' "$ELOG" | head -1)）"

echo
echo "=== 4 第二条腿：不带 --secure（老 ECU 上 0x11 走「不支持」兜底） ==="
cleanup
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 10 \
        --flash --flash-block 34 --flash-max 65536 > "$ELOG2" 2>&1 &
STUB_PID2=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT2" --seconds 8 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG2" 2>&1 &
sleep 1.2
python3 "$CHECK" "$PORT2" legacy > "$OUT2" 2>&1
cat "$OUT2"
grep -q "^FAIL=0$" "$OUT2" && ok "老路径腿：脚本自身 0 失败" || bad "老路径腿脚本失败"

g2() { grep -m1 "^$1=" "$OUT2" 2>/dev/null | cut -d= -f2; }
[ "$(g2 LEGACY_11)" = "31" ] \
    && ok "不带 --secure：0x11 走「不支持」兜底（7F 11 31，M15/M16 的回归不受影响）" || bad "LEGACY_11=$(g2 LEGACY_11)"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M17 全绿 —— 复位真的带走了该带的：会话、解锁、锁计数、（硬复位时）镜像；留下了不该丢的（软复位后的镜像）。"
    exit 0
fi
exit 1
