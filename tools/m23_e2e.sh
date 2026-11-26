#!/usr/bin/env bash
# =============================================================================
# m23_e2e.sh —— M23 验收：钥匙表落盘（重启后吊销还在、坏文件不猜、人重建才回默认）
#
# 用法： bash tools/m23_e2e.sh [端口A] [端口B]      默认 13489 / 13490
#
# 这一步要立住的判据：
#   · "吊销"必须活过重启 —— 否则吊销只是内存里的一句话，断电就复活；
#   · 文件**不存在**（第一次上电）和文件**读不懂**（坏了）是两件事：
#     前者铺默认两把，后者表按空处理、谁都验不过，**绝不套默认**；
#   · 坏表期间不许再写（7F 31 22）：半截的表说明上一笔没落干净，
#     补一笔等于用新表悄悄盖掉旧表里可能还活着的吊销记录；
#   · 重建必须是**人说的话**（--reset-key-store），不能自动。
#
# 四个阶段各起一个新进程 —— 这一步验的就是"进程没了，表还在不在"。
# =============================================================================
set -u

PORT_A=${1:-13489}
PORT_B=${2:-13490}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m23_check.py
STORE=/tmp/m23_keys.txt
ELOG=/tmp/m23_ecu.log
SLOG=/tmp/m23_gw.log
OUT=/tmp/m23_check.txt

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
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m23_check.py 自身编译不过（先 py_compile）"; exit 1; }


# 每个阶段共用的起法：起 ECU（带 --key-store）+ 起网关
start_phase() {   # $1=端口 $2=秒数 $3..=ECU 额外参数
    local port=$1 secs=$2
    shift 2
    cleanup
    : > "$ELOG"
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
            --vin LSVZZ0000B7654321 --hw HW02 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure --require-compat \
            --key-store "$STORE" "$@" > "$ELOG" 2>&1 &
    PHASE_STUB=$!
    stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
            --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
    sleep 1.2
}

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2-; }

# =============================================================================
echo "=== 1 阶段一：第一次上电（没有文件 → 铺默认两把并写盘） ==="
cleanup
rm -f "$STORE" "$STORE.tmp"
start_phase "$PORT_A" 12

grep -q "钥匙表：$STORE —— 第一次上电" "$ELOG" \
    && ok "启动行说清「文件不存在 → 第一次上电」（不是「坏了」）" || bad "启动行没有说明第一次上电"
[ -f "$STORE" ] && ok "默认两把立刻落盘（不用等装钥匙）" || bad "盘上没有 $STORE"
grep -q "^K 0001 00 " "$STORE" 2>/dev/null \
    && ok "盘上文件是可读的文本（K 0001 00 …）" || bad "盘上文件形状不对"

python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "阶段一脚本自身 0 失败" || bad "阶段一有失败项"
[ "$(grab P1_TABLE_BOOT)" = "0001=00,0002=00" ] && ok "首启读出默认两把" || bad "P1_TABLE_BOOT=$(grab P1_TABLE_BOOT)"
[ "$(grab P1_INSTALL_3)" = "7101020600" ] && ok "装 3 号 → 00（并写盘）" || bad "P1_INSTALL_3=$(grab P1_INSTALL_3)"
[ "$(grab P1_REVOKE_1)" = "7101020700" ] && ok "吊销 1 号 → 00" || bad "P1_REVOKE_1=$(grab P1_REVOKE_1)"
[ "$(grab P1_TABLE_AFTER_REVOKE)" = "0001=02,0002=00,0003=00" ] && ok "表里 0001=02" || bad "P1_TABLE_AFTER_REVOKE=$(grab P1_TABLE_AFTER_REVOKE)"
[ "$(grab P1_INSTALL_4)" = "7101020600" ] && ok "装 4 号 → 00" || bad "P1_INSTALL_4=$(grab P1_INSTALL_4)"
wait "$PHASE_STUB" 2>/dev/null
grep -q "^K 0001 02 " "$STORE" && ok "盘上 1 号写成 02（吊销落盘，不是只改内存）" || bad "盘上 1 号不是 02"

# =============================================================================
echo
echo "=== 2 阶段二：重启（同一个文件 → 吊销还在） ==="
start_phase "$PORT_A" 12
grep -q "钥匙表：$STORE —— 读到 4 把" "$ELOG" \
    && ok "启动行说清「读到了 4 把」（不是第一次上电）" || bad "启动行没有说明读到了几把"

python3 "$CHECK" "$PORT_A" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "阶段二脚本自身 0 失败" || bad "阶段二有失败项"
[ "$(grab P2_TABLE_AFTER_REBOOT)" = "0001=02,0002=00,0003=00,0004=00" ] \
    && ok "**重启后吊销还在**（0001=02，这就是 M23 的全部意义）" || bad "P2_TABLE_AFTER_REBOOT=$(grab P2_TABLE_AFTER_REBOOT)"
[ "$(grab P2_INSTALL_EXISTING)" = "7101020601" ] && ok "重启后同 id 仍不许覆盖（01）" || bad "P2_INSTALL_EXISTING=$(grab P2_INSTALL_EXISTING)"
[ "$(grab P2_PRECHECK_REVOKED_KEY)" = "7F3131" ] && ok "重启后被吊销的钥匙仍被拒（0205 预检 7F 31 31）" || bad "P2_PRECHECK_REVOKED_KEY=$(grab P2_PRECHECK_REVOKED_KEY)"
[ "$(grab P2_PRECHECK_NEW_KEY)" = "7101020500" ] && ok "重启后 4 号签的包预检通过（钥匙表是活的）" || bad "P2_PRECHECK_NEW_KEY=$(grab P2_PRECHECK_NEW_KEY)"
wait "$PHASE_STUB" 2>/dev/null

# =============================================================================
echo
echo "=== 3 阶段三：把文件写坏（砍掉尾巴）→ 启动判 Corrupt，表按空处理 ==="
python3 - "$STORE" <<'PY'
import sys
p = sys.argv[1]
with open(p, "rb") as f:
    data = f.read()
with open(p, "wb") as f:
    f.write(data[:-10])          # 模拟写到一半断电
print("写坏了：%d → %d 字节" % (len(data), len(data) - 10))
PY

start_phase "$PORT_B" 12
grep -q "钥匙表：$STORE —— 文件坏了，不采用" "$ELOG" \
    && ok "启动行明确说「文件坏了，不采用」（不是悄悄当空表）" || bad "启动行没有说文件坏了"
grep -q "校验和" "$ELOG" && ok "理由说得出是校验和不对（半截/被改）" || bad "日志没提校验和"
grep -q "绝不套默认" "$ELOG" || true   # 说明性的，不判定

python3 "$CHECK" "$PORT_B" 3 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "阶段三脚本自身 0 失败" || bad "阶段三有失败项"
[ "$(grab P3_TABLE_EMPTY)" = "(空)" ] && ok "坏文件 → 表是**空的**，不是默认两把" || bad "P3_TABLE_EMPTY 不是空（$(grab P3_TABLE_EMPTY)）"
[ "$(grab P3_PRECHECK_ANY_KEY)" = "7F3131" ] && ok "空表时谁都验不过（不作为比猜错好）" || bad "P3_PRECHECK_ANY_KEY=$(grab P3_PRECHECK_ANY_KEY)"
[ "$(grab P3_INSTALL_LOCKED)" = "7F3122" ] && ok "坏表上装钥匙 → 7F 31 22（不许在半截表上再写）" || bad "P3_INSTALL_LOCKED=$(grab P3_INSTALL_LOCKED)"
[ "$(grab P3_STATE_LOCKED)" = "7F3122" ] && ok "坏表上改状态 → 7F 31 22" || bad "P3_STATE_LOCKED=$(grab P3_STATE_LOCKED)"
wait "$PHASE_STUB" 2>/dev/null
grep -q "钥匙表：$STORE；坏文件 1 次；落盘失败 0 次" "$ELOG" \
    && ok "退账：坏文件 1 次、落盘失败 0 次" || bad "退账的坏文件计数不对"

# =============================================================================
echo
echo "=== 4 阶段四：--reset-key-store（人明确说重建，才回默认两把） ==="
start_phase "$PORT_B" 12 --reset-key-store
grep -q "重建并" "$ELOG" && ok "启动行说清是 --reset-key-store 重建的" || bad "启动行没提重建"

python3 "$CHECK" "$PORT_B" 4 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "阶段四脚本自身 0 失败" || bad "阶段四有失败项"
[ "$(grab P4_TABLE_RESET)" = "0001=00,0002=00" ] && ok "重建回默认两把（1 号又能验了）" || bad "P4_TABLE_RESET=$(grab P4_TABLE_RESET)"
[ "$(grab P4_PRECHECK_AFTER_RESET)" = "7101020500" ] && ok "1 号签的包预检通过（00）—— 重建是人说的话，不是自动复活" || bad "P4_PRECHECK_AFTER_RESET=$(grab P4_PRECHECK_AFTER_RESET)"
[ "$(grab P4_INSTALL_AFTER_RESET)" = "7101020600" ] && ok "重建之后装钥匙恢复正常" || bad "P4_INSTALL_AFTER_RESET=$(grab P4_INSTALL_AFTER_RESET)"
wait "$PHASE_STUB" 2>/dev/null
grep -q "^K 0001 00 " "$STORE" && ok "盘上文件被重建（1 号回到 00）" || bad "盘上文件没重建"

cleanup
rm -f "$STORE" "$STORE.tmp"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M23 全绿 —— 钥匙表活过重启：吊销还在、坏文件不猜、半截表不再写、重建要人说话。"
    exit 0
fi
exit 1
