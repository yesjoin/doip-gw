#!/usr/bin/env bash
# =============================================================================
# m19_e2e.sh —— M19 验收：刷写前置条件检查（0x22 读 / 0x2E 写 / 0x31 01 0203）
#
# 用法： bash tools/m19_e2e.sh [端口A] [端口B]        默认 13481 / 13482
#
# 两条腿，同一个脚本，靠 ECU 报的电压区分：
#   · 腿一 12400 mV：身份读得出来、指纹写得进去、前置检查 00、0x34 放行；
#   · 腿二 11000 mV：F1A5 读出来就是 11000、前置检查 01、0x34 直接 7F 34 22。
#
# 这一步要立住的判据：
#   "不能刷"有两种说法 —— 请求错了（NRC 0x7F/0x33/0x13/0x31）和 现在不合适（正响应状态 01 / NRC 0x22）。
#   诊断仪拿到哪一种，决定它该改请求还是该去充电。
# =============================================================================
set -u

PORT_A=${1:-13481}
PORT_B=${2:-13482}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m19_check.py
ELOG=/tmp/m19_ecu.log
SLOG=/tmp/m19_gw.log
OUT=/tmp/m19_check.txt

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

cleanup
echo "=== 1 腿一：电压 12400 mV（健康电池） ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 22 \
        --flash --flash-block 34 --flash-max 65536 --secure \
        --battery-mv 12400 > "$ELOG" 2>&1 &
STUB1_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT_A" --seconds 20 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "身份：0x22 读 F187 零件号" "$ELOG" \
    && ok "启动行说清了能读哪些身份、指纹可写" || bad "启动行没提身份 DID"
grep -q "前置：0x31 01 0203 检查能不能刷" "$ELOG" \
    && ok "启动行说清了前置检查与电压门槛" || bad "启动行没提前置检查"

echo
echo "=== 2 场景（m19_check.py 12400：读身份 → 三道拦 → 00 → 写指纹 → 0x34） ==="
python3 "$CHECK" "$PORT_A" 12400 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿一脚本自身 0 失败" || bad "腿一脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab ACT_CODE)" = "10" ] && ok "路由激活 0x10" || bad "ACT_CODE=$(grab ACT_CODE)"
[ "$(grab VIN)" = "LSVZZ0000B7654321" ] && ok "F190 VIN 照旧（M15 起的老 DID 没被改坏）" || bad "VIN=$(grab VIN)"
[ "$(grab PART_NO)" = "PART-ABC1234" ] && ok "F187 零件号读得到（刷之前先认车）" || bad "PART_NO=$(grab PART_NO)"
[ "$(grab SW_VERSION)" = "SW-1.0.3" ] && ok "F188 软件版本读得到" || bad "SW_VERSION=$(grab SW_VERSION)"
[ "$(grab SERIAL)" = "ECU-A-0007" ] && ok "F18C 序列号读得到" || bad "SERIAL=$(grab SERIAL)"
[ "$(grab BATTERY)" = "3070" ] && ok "F1A5 电压 12400 mV → 30 70（大端能手算）" || bad "BATTERY=$(grab BATTERY)"
[ "$(grab FINGERPRINT_INIT)" = "62F18400000000" ] && ok "F184 指纹初值 0x00000000" || bad "FINGERPRINT_INIT=$(grab FINGERPRINT_INIT)"
[ "$(grab NRC_UNKNOWN_DID)" = "31" ] && ok "读不认识的 DID → 7F 22 31" || bad "NRC_UNKNOWN_DID=$(grab NRC_UNKNOWN_DID)"

[ "$(grab NRC_2E_DEFAULT)" = "7F" ] && ok "默认会话写指纹 → 7F 2E 7F（会话不对）" || bad "NRC_2E_DEFAULT=$(grab NRC_2E_DEFAULT)"
[ "$(grab PRECHECK_DEFAULT)" = "7101020301" ] && ok "默认会话问能不能刷 → 正响应状态 01（请求合法，是条件不满足）" || bad "PRECHECK_DEFAULT=$(grab PRECHECK_DEFAULT)"
[ "$(grab SESSION_PROG)" = "5002003201F4" ] && ok "切编程会话 0x10 02" || bad "SESSION_PROG=$(grab SESSION_PROG)"
[ "$(grab NRC_2E_LOCKED)" = "33" ] && ok "编程会话但没解锁就写 → 7F 2E 33（钥匙没插）" || bad "NRC_2E_LOCKED=$(grab NRC_2E_LOCKED)"
[ "$(grab PRECHECK_LOCKED)" = "7101020301" ] && ok "没解锁时前置检查仍是 01" || bad "PRECHECK_LOCKED=$(grab PRECHECK_LOCKED)"
[ "$(grab UNLOCK)" = "OK" ] && ok "0x27 解锁" || bad "UNLOCK=$(grab UNLOCK)"
[ "$(grab NRC_2E_LEN)" = "13" ] && ok "写 F184 只给 3 字节 → 7F 2E 13" || bad "NRC_2E_LEN=$(grab NRC_2E_LEN)"
[ "$(grab NRC_2E_READONLY)" = "31" ] && ok "写只读 DID F187 → 7F 2E 31" || bad "NRC_2E_READONLY=$(grab NRC_2E_READONLY)"
[ "$(grab PRECHECK_OK)" = "7101020300" ] && ok "电压够 + 编程会话 + 已解锁 + 不在下载 → 71 01 02 03 00" || bad "PRECHECK_OK=$(grab PRECHECK_OK)"
[ "$(grab WRITE_FP)" = "6EF184" ] && ok "0x2E 写 F184 → 6E F1 84" || bad "WRITE_FP=$(grab WRITE_FP)"
[ "$(grab FP_READBACK)" = "62F184A1B2C3D4" ] && ok "写进去的指纹读回来一模一样（跨请求保存）" || bad "FP_READBACK=$(grab FP_READBACK)"
[ "$(grab ERASE)" = "7101FF00" ] && ok "0x31 FF00 擦除" || bad "ERASE=$(grab ERASE)"
[ "$(grab DOWNLOAD)" = "74200022" ] && ok "电压正常时 0x34 放行" || bad "DOWNLOAD=$(grab DOWNLOAD)"
[ "$(grab PRECHECK_MIDDLE)" = "7101020301" ] && ok "正在下载时问能不能刷 → 01（不在下载中这条不过）" || bad "PRECHECK_MIDDLE=$(grab PRECHECK_MIDDLE)"
[ "$(grab BLOCK_1)" = "7601" ] && ok "0x36 收块" || bad "BLOCK_1=$(grab BLOCK_1)"
IMG_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*29+5)&0xFF for i in range(8)])) & 0xFFFFFFFF))')
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ] && ok "0x37 的 CRC 仍是 $IMG_CRC" || bad "EXIT_CRC=$(grab EXIT_CRC)"
[ "$(grab PRECHECK_AFTER)" = "7101020300" ] && ok "下载收尾之后再问 → 回到 00" || bad "PRECHECK_AFTER=$(grab PRECHECK_AFTER)"

echo
echo "=== 3 等腿一 ECU 退场，核对账 ==="
wait "$STUB1_PID" 2>/dev/null
grep -q "0x34 被拒：电压" "$ELOG" && bad "腿一不该出现电压拒绝" || ok "腿一没有误伤（电压够时 0x34 没被拒）"
line=$(grep -o "前置：检查 [0-9]* 次 → 可刷 [0-9]* 次 / 不可刷 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "检查 5 次" && ok "账：检查 5 次（默认/未解锁/解锁后/下载中/收尾后）" || bad "检查次数对不上（$line）"
echo "$line" | grep -q "可刷 2 次" && ok "账：可刷 2 次（解锁后 + 下载收尾后）" || bad "可刷次数对不上（$line）"
echo "$line" | grep -q "不可刷 3 次" && ok "账：不可刷 3 次（默认会话 / 未解锁 / 下载中途）" || bad "不可刷次数对不上（$line）"
grep -q "指纹 0xA1B2C3D4" "$ELOG" && ok "账：指纹停在 0xA1B2C3D4" || bad "指纹账对不上"

echo
echo "=== 4 腿二：电压 11000 mV（亏电池，这台车现在不该刷） ==="
cleanup
: > "$ELOG"
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 14 \
        --flash --flash-block 34 --flash-max 65536 --secure \
        --battery-mv 11000 > "$ELOG" 2>&1 &
STUB2_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT_B" --seconds 12 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

python3 "$CHECK" "$PORT_B" 11000 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "腿二脚本自身 0 失败" || bad "腿二脚本里有失败项"

[ "$(grab BATTERY)" = "2AF8" ] && ok "F1A5 读出来是 2AF8 = 11000 mV（电压是读出来的，不是猜的）" || bad "BATTERY=$(grab BATTERY)"
[ "$(grab PRECHECK_LOW)" = "7101020301" ] && ok "前置检查 01（四条里电压这条不过）" || bad "PRECHECK_LOW=$(grab PRECHECK_LOW)"
[ "$(grab NRC_34_LOW_VOLT)" = "7F3422" ] && ok "电压不够还发 0x34 → 7F 34 22（条件不满足，别开始）" || bad "NRC_34_LOW_VOLT=$(grab NRC_34_LOW_VOLT)"
[ "$(grab PRECHECK_AFTER_DENY)" = "7101020301" ] && ok "被拒之后没留下半截下载状态（再问仍是 01，不是 00）" || bad "PRECHECK_AFTER_DENY=$(grab PRECHECK_AFTER_DENY)"

echo
echo "=== 5 等腿二 ECU 退场，核对日志 ==="
wait "$STUB2_PID" 2>/dev/null
grep -q "0x34 被拒：电压 11000 mV 低于门槛 11500 mV" "$ELOG" \
    && ok "日志把电压拒绝的原因写清楚了" || bad "日志里没有电压拒绝"
grep -q "电压 11000 mV ≥ 11500 ✗" "$ELOG" \
    && ok "前置检查逐条打出了哪条不过（电压 ✗）" || bad "日志里没有逐条结论"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M19 全绿 —— 刷之前先问「这是哪台、装了什么、电够不够」，不满足就别进 0x34。"
    exit 0
fi
exit 1
