#!/usr/bin/env bash
# =============================================================================
# m27_e2e.sh —— M27 验收：路由激活的"入场券"
#
# 用法： bash tools/m27_e2e.sh [端口A] [端口B]      默认 13498 / 13499
#
# 这一步要立住的判据：
#   · 没开票时行为**一点不变**（老客户端、7 字节变体、诊断请求全都不受影响）；
#   · 开了票，对的进：0x10，而且进去之后 UDS 照常通；
#   · 开了票，不对的挡：0x04 缺认证，而且**被挡的连接发不了诊断**（拒了就是真拒）；
#   · 票是绑源地址的：拿 0x0E01 的票冒充 0x0E00，一样挡；
#   · 两张票各自成立：两台诊断仪各带各的票，都进得来。
#
# 段一：不开票（回归腿）。段二：开票（新能力腿）。
# =============================================================================
set -u

PORT_A=${1:-13498}
PORT_B=${2:-13499}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m27_check.py
KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
ELOG=/tmp/m27_ecu.log
SLOG_A=/tmp/m27_gw_plain.log
SLOG_B=/tmp/m27_gw_key.log
OUT=/tmp/m27_check.txt

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
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m27_check.py 自身编译不过"; exit 1; }

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2-; }

start_one() {   # $1=端口 $2=秒数 $3=要不要开票(1/0)
    local port=$1 secs=$2 withkey=${3:-0}
    cleanup
    : > "$ELOG"
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
            --vin LSVZZ0000B7654321 --hw HW02 --seconds "$secs" > "$ELOG" 2>&1 &
    if [ "$withkey" = "1" ]; then
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0003:7A0:7A8:ECU_A --tester-key "$KEY" > "$SLOG_B" 2>&1 &
    else
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0003:7A0:7A8:ECU_A > "$SLOG_A" 2>&1 &
    fi
    sleep 1.2
}

# =============================================================================
echo "=== 1 段一：不开票 —— 老路径必须一点不变（回归腿）==="
start_one "$PORT_A" 12 0

grep -q "路由激活凭据：关" "$SLOG_A" \
    && ok "横幅明说「凭据关」（没开票的网关必须看得出来）" || bad "横幅没报凭据状态"

python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段一脚本自身 0 失败" || bad "段一有失败项"
[ "$(grab TOKEN)" != "" ] && ok "python 独立算出票（$(grab TOKEN)），和 C++ 实现在段二对账" || bad "票没算出来"
grep -q "凭据：通过" "$SLOG_A" && bad "没开票却出现了凭据账" || ok "没开票时不出凭据账（不假装验过）"

wait 2>/dev/null

# =============================================================================
echo
echo "=== 2 段二：开票 —— 对的进、没票挡、别人的票挡、7 字节挡 ==="
start_one "$PORT_B" 14 1

grep -q "路由激活凭据：开" "$SLOG_B" \
    && ok "横幅明说「凭据开」，并且提醒「挡住≠安全」（4 字节静态票可重放）" || bad "开票的横幅不对"

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段二脚本自身 0 失败" || bad "段二有失败项"

TOK=$(grab TOKEN)
grep -q "token $TOK" "$SLOG_B" \
    && ok "网关日志里的票 = python 独立算出的 $TOK（两条实现撞上了）" || bad "日志里没有 token $TOK"

grep -q "凭据已验证" "$SLOG_B" && ok "通过的那次在日志里留了「凭据已验证」" || bad "日志没有验证通过记录"
grep -q "凭据不对" "$SLOG_B"    && ok "被挡的那几次在日志里留了「凭据不对」" || bad "日志没有拒绝记录"

wait 2>/dev/null
grep -q "凭据：通过 2 次，挡回 3 次" "$SLOG_B" \
    && ok "退账：通过 2 次 / 挡回 3 次（0x0E00 与 0x0E01 各一次，另加三个被挡的）" \
    || bad "退账计数不对：$(grep '凭据：通过' "$SLOG_B" | tail -1)"

# =============================================================================
echo
echo "=== 汇总：通过 $pass 项，失败 $fail 项 ==="
[ "$fail" = "0" ] || exit 1
