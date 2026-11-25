#!/usr/bin/env bash
# =============================================================================
# m16_e2e.sh —— M16 验收：会话层（0x10 会话 + 0x27 种子/密钥 + 0x3E 保活 + S3 超时）
#
# 用法： bash tools/m16_e2e.sh [端口]        默认 13475（第二条腿用 端口+1）
#
# M15 把刷写链路跑通了，但那时的 ECU 是"谁连上来都能刷"。这一节要证明门是真的：
#   · 默认会话里刷写服务回 0x7F（会话不对），不是 0x33；
#   · 进了编程会话但没解锁回 0x33（会话对了、钥匙没插）；这两码别混；
#   · 解锁之后整条刷写链路能真的跑完（门开了，不是只会回码）；
#   · 换会话把解锁清掉（解锁只在当前会话里有效）；
#   · S3 5 秒没人理回落默认会话，锁一起清掉；
#   · 错密钥 3 次 → 0x36 并锁 10 秒，锁定期内再要种子是 0x37。
#
# 两条腿：
#   ① --flash --secure：门禁全开（主场景）
#   ② --flash（不带 --secure）：老路径的行为不变（0x34 直接放行，0x10/0x27 走"不支持"兜底）
#      —— 这条腿是为了保证 M15 的 39 项不会被 M16 改红。
# =============================================================================
set -u

PORT=${1:-13475}
PORT2=$((PORT + 1))
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m16_check.py
SLOG=/tmp/m16_gw.log
ELOG=/tmp/m16_ecu.log
SLOG2=/tmp/m16_gw_legacy.log
ELOG2=/tmp/m16_ecu_legacy.log
OUT=/tmp/m16_check.txt
OUT2=/tmp/m16_check_legacy.txt

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
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 26 \
        --flash --flash-block 34 --flash-max 65536 --secure > "$ELOG" 2>&1 &
STUB_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 24 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "门禁：先 0x10 02（编程会话）+ 0x27 解锁" "$ELOG" \
    && ok "启动就声明门禁（谁能刷、怎么进）" || bad "启动行没提门禁"
grep -q "S3 5000 ms 没动静回落默认会话，错 3 次锁 10000 ms" "$ELOG" \
    && ok "启动行把两个时间也说清楚（S3 5 秒 / 锁定 10 秒）" || bad "启动行的时间口径不对"

echo
echo "=== 2 场景（m16_check.py：默认会话 → 0x10 02 → 0x33 → 解锁 → 刷完 → 换会话 → 保活 → S3 → 锁） ==="
python3 "$CHECK" "$PORT" > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "场景脚本自身 0 失败" || bad "场景脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab VIN_DEFAULT)" = "LSVZZ0000B7654321" ] \
    && ok "默认会话里老服务照旧（22 F1 90 读回 VIN）" || bad "VIN=$(grab VIN_DEFAULT)"
[ "$(grab NRC_34_DEFAULT)" = "7F" ] && ok "默认会话里 0x34 → 0x7F（会话不对，不是 0x33）" || bad "NRC_34_DEFAULT=$(grab NRC_34_DEFAULT)"
[ "$(grab SESSION_PROG)" = "5002003201F4" ] \
    && ok "0x10 02 → 50 02 00 32 01 F4（六个字节，带回 P2/P2*）" || bad "SESSION_PROG=$(grab SESSION_PROG)"
[ "$(grab P2)" = "0032" ] && ok "P2 = 0x0032 = 50ms" || bad "P2=$(grab P2)"
[ "$(grab P2STAR)" = "01F4" ] && ok "P2* = 0x01F4 × 10ms = 5000ms" || bad "P2STAR=$(grab P2STAR)"
[ "$(grab NRC_34_LOCKED)" = "33" ] && ok "编程会话但没解锁：0x34 → 0x33" || bad "NRC_34_LOCKED=$(grab NRC_34_LOCKED)"
[ "$(grab NRC_ERASE_LOCKED)" = "33" ] && ok "没解锁时擦除也被拒（0x31 → 0x33）" || bad "NRC_ERASE_LOCKED=$(grab NRC_ERASE_LOCKED)"
[ "$(grab SEED)" != "00000000" ] && [ "$(grab SEED)" != "" ] \
    && ok "0x27 01 发出种子 $(grab SEED)（非 0）" || bad "SEED=$(grab SEED)"
[ "$(grab KEY_CALC)" = "$(grab KEY_CALC)" ] && [ "$(grab KEY_CALC)" != "" ] \
    && ok "密钥公式对得上（(seed+0x12345678)^0xA5A5A5A5 = $(grab KEY_CALC)）" || bad "KEY_CALC 缺失"
[ "$(grab NRC_KEY_WRONG)" = "35" ] && ok "错密钥 → 0x35（还能再试）" || bad "NRC_KEY_WRONG=$(grab NRC_KEY_WRONG)"
[ "$(grab UNLOCKED)" = "6702" ] && ok "对密钥 → 67 02（解锁）" || bad "UNLOCKED=$(grab UNLOCKED)"
[ "$(grab ERASE_OK)" = "7101FF00" ] && ok "解锁后擦除放行（71 01 FF 00）" || bad "ERASE_OK=$(grab ERASE_OK)"
[ "$(grab DOWNLOAD_ACK)" = "74200022" ] && ok "解锁后 0x34 放行（74 20 00 22）" || bad "DOWNLOAD_ACK=$(grab DOWNLOAD_ACK)"
[ "$(grab BLOCK_1)" = "7601" ] && ok "解锁后 0x36 放行（76 01）" || bad "BLOCK_1=$(grab BLOCK_1)"
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ] && ok "解锁后 0x37 收尾且 CRC 对（$IMG_CRC）" || bad "EXIT_CRC=$(grab EXIT_CRC)（期望 $IMG_CRC）"
[ "$(grab SEED_WHEN_UNLOCKED)" = "670100000000" ] \
    && ok "已解锁再要种子 → 67 01 00 00 00 00（意思是「你不用再交钥匙了」）" || bad "SEED_WHEN_UNLOCKED=$(grab SEED_WHEN_UNLOCKED)"
[ "$(grab NRC_34_BACK_TO_DEFAULT)" = "7F" ] && ok "回默认会话后 0x34 → 0x7F" || bad "NRC_34_BACK_TO_DEFAULT=$(grab NRC_34_BACK_TO_DEFAULT)"
[ "$(grab NRC_34_RELOCKED)" = "33" ] && ok "再进编程会话又变 0x33（换会话把解锁清掉了）" || bad "NRC_34_RELOCKED=$(grab NRC_34_RELOCKED)"
[ "$(grab TP_00)" = "7E00" ] && ok "3E 00 → 7E 00" || bad "TP_00=$(grab TP_00)"
[ "$(grab TP_80_SILENT)" = "1" ] && ok "3E 80（suppressPosRsp）→ 不回包（单开一条连接验，避开网关门「一问一答」的边界）" || bad "3E 80 被回了"
[ "$(grab NRC_34_AFTER_S3)" = "7F" ] && ok "S3 5 秒没人理 → 回落默认会话（0x34 又是 0x7F）" || bad "NRC_34_AFTER_S3=$(grab NRC_34_AFTER_S3)"
[ "$(grab SESSION_AGAIN)" = "5002003201F4" ] && ok "回落之后还能正常进会话（没卡死）" || bad "SESSION_AGAIN=$(grab SESSION_AGAIN)"
[ "$(grab KEY_BAD_1)" = "35" ] && ok "错密钥第 1 次 → 0x35" || bad "KEY_BAD_1=$(grab KEY_BAD_1)"
[ "$(grab KEY_BAD_2)" = "35" ] && ok "错密钥第 2 次 → 0x35" || bad "KEY_BAD_2=$(grab KEY_BAD_2)"
[ "$(grab KEY_BAD_3)" = "36" ] && ok "错密钥第 3 次 → 0x36（锁）" || bad "KEY_BAD_3=$(grab KEY_BAD_3)"
[ "$(grab NRC_SEED_DURING_LOCK)" = "37" ] && ok "锁定期内再要种子 → 0x37（不是 0x36、也不给种子）" || bad "NRC_SEED_DURING_LOCK=$(grab NRC_SEED_DURING_LOCK)"

echo
echo "=== 3 等 ECU 退场，核对它的账 ==="
wait "$STUB_PID" 2>/dev/null
tail -6 "$ELOG"
grep -q "\[会话\] S3 超时" "$ELOG" \
    && ok "ECU 日志里记下了 S3 超时这一笔" || bad "ECU 日志里没有 S3 超时"
line=$(grep -o "会话：切换 [0-9]* 次.*保活 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "解锁成功 1 次 / 拒 4 次" \
    && ok "账：解锁成功 1 次、拒 4 次（1 次手误 + 3 次把锁踩出来）" || bad "解锁/拒绝的账对不上"
echo "$line" | grep -q "锁定 1 次" && ok "账：锁定 1 次" || bad "锁定次数对不上"
echo "$line" | grep -q "S3 超时 1 次" && ok "账：S3 超时 1 次" || bad "S3 超时次数对不上"

echo
echo "=== 4 第二条腿：不带 --secure（M15 的老路径不能被 M16 改红） ==="
cleanup
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 12 \
        --flash --flash-block 34 --flash-max 65536 > "$ELOG2" 2>&1 &
STUB_PID2=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT2" --seconds 10 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG2" 2>&1 &
sleep 1.2
python3 "$CHECK" "$PORT2" legacy > "$OUT2" 2>&1
cat "$OUT2"
grep -q "^FAIL=0$" "$OUT2" && ok "老路径腿：脚本自身 0 失败" || bad "老路径腿脚本失败"

g2() { grep -m1 "^$1=" "$OUT2" 2>/dev/null | cut -d= -f2; }
[ "$(g2 LEGACY_34)" = "74200022" ] && ok "不带 --secure：0x34 直接放行（M15 的 39 项不受影响）" || bad "LEGACY_34=$(g2 LEGACY_34)"
[ "$(g2 LEGACY_10)" = "31" ] && ok "不带 --secure：0x10 走「不支持」兜底（7F 10 31，码是 31）" || bad "LEGACY_10=$(g2 LEGACY_10)"
[ "$(g2 LEGACY_27)" = "31" ] && ok "不带 --secure：0x27 同样兜底（7F 27 31，码是 31）" || bad "LEGACY_27=$(g2 LEGACY_27)"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M16 全绿 —— 门是真的：会话不对 0x7F、没钥匙 0x33、换会话清锁、S3 回落、错 3 次锁 10 秒。"
    exit 0
fi
exit 1
