#!/usr/bin/env bash
# =============================================================================
# m18_e2e.sh —— M18 验收：刷写包完整性（SHA-256 + 76 字节清单 + 标签）
#
# 用法： bash tools/m18_e2e.sh [端口]        默认 13479
#
# M15 的 0x37 带 CRC-32，它证明"传的过程没出错"，但 CRC 是线性的：
# 换掉镜像里的字节再补一个补偿值，CRC 照样能对上。M18 加的是"包的身份"：
#   · 清单结构错（长度 / magic / 版本 / 不认识钥匙）→ NRC；
#   · 清单内容错（标签 / 长度 / 哈希）→ 正响应 01；
#   · 别人把镜像整个换一份、清单还是原来那份 → 哈希不符（这就是"换包"）；
#   · 没有镜像时验签 → 0x22（和 M15 的空镜像校验同一个条件）。
#
# 一条腿：--flash --secure（FF02 和 FF00/FF01 一样受门禁保护）。
# M15/M16/M17 的回归由它们各自的脚本负责，这里只验"新加的这一层"。
# =============================================================================
set -u

PORT=${1:-13479}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m18_check.py
SLOG=/tmp/m18_gw.log
ELOG=/tmp/m18_ecu.log
OUT=/tmp/m18_check.txt

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
IMG2_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*7+0xA0)&0xFF for i in range(8)])) & 0xFFFFFFFF))')

cleanup
echo "=== 1 启动：网关 + 一台带 --flash --secure 的 ECU ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 22 \
        --flash --flash-block 34 --flash-max 65536 --secure > "$ELOG" 2>&1 &
STUB_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 20 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "验签：0x31 01 FF02 收 76 字节清单" "$ELOG" \
    && ok "启动行说清了清单的格式与认识的钥匙" || bad "启动行没提验签"

echo
echo "=== 2 场景（m18_check.py：正例 → 内容错 01 → 结构错 NRC → 换包 → 空镜像） ==="
python3 "$CHECK" "$PORT" > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "场景脚本自身 0 失败" || bad "场景脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab NRC_FF02_DEFAULT)" = "7F" ] \
    && ok "没解锁时 FF02 也被门挡住（0x7F，和 FF00/FF01 一样是刷写例程）" || bad "NRC_FF02_DEFAULT=$(grab NRC_FF02_DEFAULT)"
[ "$(grab UNLOCK)" = "OK" ] && ok "解锁" || bad "UNLOCK=$(grab UNLOCK)"
[ "$(grab ERASE)" = "7101FF00" ] && ok "擦除" || bad "ERASE=$(grab ERASE)"
[ "$(grab DOWNLOAD)" = "74200022" ] && ok "0x34 放行" || bad "DOWNLOAD=$(grab DOWNLOAD)"
[ "$(grab BLOCK_1)" = "7601" ] && ok "0x36 收下一块" || bad "BLOCK_1=$(grab BLOCK_1)"
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ] && ok "0x37 的 CRC 仍是 $IMG_CRC（M15 那层没被改）" || bad "EXIT_CRC=$(grab EXIT_CRC)"
[ "$(grab VERIFY_OK)" = "7101FF0200" ] \
    && ok "清单与镜像一致 → 71 01 FF 02 00（验签通过）" || bad "VERIFY_OK=$(grab VERIFY_OK)"
[ "$(grab BAD_TAG)" = "7101FF0201" ] \
    && ok "标签不符 → 正响应 71 01 FF 02 01（不是 NRC：请求合法，是包不对）" || bad "BAD_TAG=$(grab BAD_TAG)"
[ "$(grab LEN_MISMATCH)" = "7101FF0201" ] \
    && ok "签名正确但长度写错 → 状态 01" || bad "LEN_MISMATCH=$(grab LEN_MISMATCH)"
[ "$(grab SHA_MISMATCH)" = "7101FF0201" ] \
    && ok "签名正确但哈希写错 → 状态 01" || bad "SHA_MISMATCH=$(grab SHA_MISMATCH)"
[ "$(grab NRC_LEN)" = "13" ] && ok "清单 75 字节 → 0x13（长度错，NRC 那一类）" || bad "NRC_LEN=$(grab NRC_LEN)"
[ "$(grab NRC_MAGIC)" = "31" ] && ok "magic 不是 DGIM → 0x31（不是我们这个格式）" || bad "NRC_MAGIC=$(grab NRC_MAGIC)"
[ "$(grab NRC_VERSION)" = "31" ] && ok "版本不认识 → 0x31" || bad "NRC_VERSION=$(grab NRC_VERSION)"
[ "$(grab NRC_UNKNOWN_KEY)" = "31" ] && ok "keyId 0x00FF 不认识 → 0x31（没这把钥匙）" || bad "NRC_UNKNOWN_KEY=$(grab NRC_UNKNOWN_KEY)"
[ "$(grab DOWNLOAD_2)" = "74200022" ] && ok "换一份镜像再刷（8 字节）" || bad "DOWNLOAD_2=$(grab DOWNLOAD_2)"
[ "$(grab BLOCK_2)" = "7601" ] && ok "第二份镜像收块" || bad "BLOCK_2=$(grab BLOCK_2)"
[ "$(grab EXIT_CRC_2)" = "$IMG2_CRC" ] && ok "第二份镜像的 CRC 是 $IMG2_CRC（确实换掉了）" || bad "EXIT_CRC_2=$(grab EXIT_CRC_2)"
[ "$(grab PACKAGE_SWAP)" = "7101FF0201" ] \
    && ok "拿原清单去验换过的镜像 → 状态 01（这就是「换包」被抓住的地方）" || bad "PACKAGE_SWAP=$(grab PACKAGE_SWAP)"
[ "$(grab RESET_HARD)" = "5101" ] && ok "硬复位清镜像（用 M17 的动作制造空镜像）" || bad "RESET_HARD=$(grab RESET_HARD)"
[ "$(grab NRC_EMPTY)" = "22" ] && ok "没有镜像时验签 → 0x22（先 0x34/0x36）" || bad "NRC_EMPTY=$(grab NRC_EMPTY)"

echo
echo "=== 3 等 ECU 退场，核对日志里的原因 ==="
wait "$STUB_PID" 2>/dev/null
grep -q "验签：镜像哈希不符" "$ELOG" \
    && ok "日志把「镜像哈希不符」写出来了（状态码只有一个字节，装不下三种原因）" || bad "日志里没有哈希不符"
grep -q "验签：标签不符" "$ELOG" \
    && ok "日志把「标签不符」写出来了" || bad "日志里没有标签不符"
# M22 之后：钥匙是从表里查的，日志说「不在钥匙表里」并把当前表一起打出来
grep -q "验签：keyId 0x00FF 不在钥匙表里" "$ELOG" \
    && ok "日志把「没这把钥匙」写出来了（还带当前的表）" || bad "日志里没有不认识钥匙"
line=$(grep -o "验签：通过 [0-9]* 次 / 不过 [0-9]* 次" "$ELOG" | head -1)
echo "      账：$line"
echo "$line" | grep -q "通过 1 次" && ok "账：通过 1 次" || bad "通过次数对不上（$line）"
echo "$line" | grep -q "不过 8 次" && ok "账：不过 8 次（内容错 3 + 结构错 4 + 换包 1）" || bad "不过次数对不上（$line）"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M18 全绿 —— 完整性分两层：CRC 管「传错没有」，哈希+标签管「这包是不是原来那份」。"
    exit 0
fi
exit 1
