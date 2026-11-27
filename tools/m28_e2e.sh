#!/usr/bin/env bash
# =============================================================================
# m28_e2e.sh —— M28 验收：把"谁"送到 CAN 侧（29 位 ID 的最低字节）
#
# 用法： bash tools/m28_e2e.sh [端口A] [端口B]      默认 13500 / 13501
#
# 这一步要立住的判据：
#   · 开 --stamp-sa：两台诊断仪拿到两个位子（0xF1 / 0xF2），ECU 从首帧 ID 里
#     读出"谁"记进流水第七格 —— **两台分得开**，落盘 v4 的 L 行是 38 字符；
#   · 11 位寻址的那台（0x7A0）没有源地址那一格：同一套动作只能记 00（不知道）；
#   · 不开 --stamp-sa（对照腿）：两台在 ECU 账上都是 0xF1，**分不开** ——
#     这就是"为什么要把源地址写下去"的反面证据；
#   · 位子会回收：会话结束退账是"还占着 0 个"（不是"发了 N 个"那种假账）。
#
# 段一：开（新能力腿）。段二：关（对照腿）。
# =============================================================================
set -u

PORT_A=${1:-13500}
PORT_B=${2:-13501}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m28_check.py
SLOG_A=/tmp/m28_gw_stamp.log
SLOG_B=/tmp/m28_gw_plain.log
OUT=/tmp/m28_check.txt
STORE_FD=/tmp/m28_fd.txt
STORE_11=/tmp/m28_11.txt
STORE_B=/tmp/m28_b.txt

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
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m28_check.py 自身编译不过"; exit 1; }

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2-; }

# $1=端口 $2=秒数 $3=要不要改写源地址(1/0)
start_fleet() {
    local port=$1 secs=$2 stamp=${3:-0}
    cleanup
    : > "$SLOG_A"; : > "$SLOG_B"
    rm -f "$STORE_FD" "$STORE_11" "$STORE_B"
    # 0x0003：11 位寻址（没有源地址那一格）
    #   --flash / --secure 是必须的：0207 改钥匙状态属于"会改这台 ECU"的动作，
    #   要先 10 02 + 27 解锁才放行（少了这两个开关，0x10 02 直接 7F 10 31）。
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
            --vin LSVZZ0000B7654321 --hw HW02 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure \
            --key-store "$STORE_11" > /tmp/m28_11.log 2>&1 &
    # 0x0006：29 位寻址 —— 收帧要按掩码（八种源地址都收），否则只认得出第一台
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 18DA00F1 --tx 18DAF100 --rx-mask 1FFFFF00 \
            --vin LSVCC0000C7654321 --hw HW03 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure \
            --key-store "$STORE_FD" > /tmp/m28_fd.log 2>&1 &
    # 0x0007：11 位，凑够三台路由（不进流水，只验路由没被搞坏）
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 7B0 --tx 7B8 \
            --vin LSVBB0000B7654321 --hw HW04 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure > /tmp/m28_b.log 2>&1 &
    if [ "$stamp" = "1" ]; then
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0003:7A0:7A8:ECU_A \
                --route 0006:18DA00F1:18DAF100:ECU_FD \
                --route 0007:7B0:7B8:ECU_B \
                --stamp-sa > "$SLOG_A" 2>&1 &
        echo "$SLOG_A" > /tmp/m28_slog
    else
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0003:7A0:7A8:ECU_A \
                --route 0006:18DA00F1:18DAF100:ECU_FD \
                --route 0007:7B0:7B8:ECU_B > "$SLOG_B" 2>&1 &
        echo "$SLOG_B" > /tmp/m28_slog
    fi
    sleep 1.5
}

# =============================================================================
echo "=== 1 段一：开 --stamp-sa —— ECU 账上两台分得开（F2 / F1）==="
start_fleet "$PORT_A" 16 1

grep -q "源地址改写：开" "$SLOG_A" \
    && ok "横幅明说「改写开」，并且提醒它破坏透明桥接（不是悄悄改）" || bad "横幅没报改写状态"

python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段一脚本自身 0 失败" || bad "段一有失败项"

# 位子的两条账必须在**激活之后**才查：横幅是启动时打的，位子是连上才发的。
grep -q "位子 1（CAN 源地址 0xF1）" "$SLOG_A" \
    && ok "第一台诊断仪发到位子 1 → CAN 源地址 0xF1（日志里是十六进制，不是十进制）" \
    || bad "日志里没看到「位子 1（CAN 源地址 0xF1）」"
grep -q "位子 2（CAN 源地址 0xF2）" "$SLOG_A" \
    && ok "第二台拿到位子 2 → 0xF2（同一个 SA 同槽、不同 SA 分槽）" || bad "日志里没看到位子 2"

[ "$(grab FD_J1_WHO)" = "F2" ] && ok "29 位 ECU 流水最新一笔记的是 F2（后到的第二台）" || bad "FD_J1_WHO=$(grab FD_J1_WHO)"
[ "$(grab FD_J2_WHO)" = "F1" ] && ok "上一笔记的是 F1（先到的第一台）—— 两台真的分开了" || bad "FD_J2_WHO=$(grab FD_J2_WHO)"
[ "$(grab B11_J1_WHO)" = "00" ] \
    && ok "11 位 ECU（0x7A0）记 00：它没有源地址那一格，不知道是谁（不编一个）" \
    || bad "B11_J1_WHO=$(grab B11_J1_WHO)"

[ "$(grep -c '^L ' "$STORE_FD")" = "2" ] && ok "29 位那台的盘上正好 2 行流水" || bad "盘上流水行数不对"
[ "$(grep '^L ' "$STORE_FD" | awk '{ print length }' | sort -u)" = "38" ] \
    && ok "v4 的 L 行是 38 字符（末尾多一格「谁」）" || bad "L 行长度不是 38"
grep -q "DOIPKEYRING 4" "$STORE_FD" && ok "盘上版本行是 4（v4）" || bad "盘上不是 v4"
grep -q "谁 F2" /tmp/m28_fd.log && ok "ECU 退账的流水里带「谁 F2」（人和机器都读得懂）" || bad "退账没带「谁」"

wait 2>/dev/null
grep -q "位子：此刻还占着 0 个" "$SLOG_A" \
    && ok "退账：连接都断了，位子全部归还（0 个没还）" || bad "退账位子数不对：$(grep '位子：' "$SLOG_A" | tail -1)"

# =============================================================================
echo
echo "=== 2 段二：不开 --stamp-sa —— 两台在 ECU 账上都是 0xF1，分不开（对照腿）==="
start_fleet "$PORT_B" 16 0

grep -q "源地址改写：关" "$SLOG_B" \
    && ok "横幅明说「改写关」（所有诊断仪在总线上都是路由表里那个源地址）" || bad "关的横幅不对"

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段二脚本自身 0 失败" || bad "段二有失败项"

[ "$(grab PLAIN_J1_WHO)" = "F1" ] && ok "对照腿：最新一笔也是 F1" || bad "PLAIN_J1_WHO=$(grab PLAIN_J1_WHO)"
[ "$(grab PLAIN_J2_WHO)" = "F1" ] && ok "对照腿：上一条还是 F1 —— 两台分不开" || bad "PLAIN_J2_WHO=$(grab PLAIN_J2_WHO)"
[ "$(grab PLAIN_SAME)" = "两台同值（改源地址之前，ECU 分不出谁是谁）" ] \
    && ok "对照腿的结论成立：不改源地址，流水的第七格就是摆设" || bad "PLAIN_SAME=$(grab PLAIN_SAME)"

wait 2>/dev/null
cleanup
rm -f "$STORE_FD" "$STORE_11" "$STORE_B" "$STORE_FD.tmp" "$STORE_11.tmp" /tmp/m28_slog

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M28 验收通过"
else
    exit 1
fi
