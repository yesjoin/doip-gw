#!/usr/bin/env bash
# =============================================================================
# m6_e2e.sh —— M6 验收：一个网关、两台 ECU、三个地址
#
# 拓扑（全在 vcan0 上）：
#
#   第三方客户端 ── DoIP ──► 网关（TCP 13461）
#                              ├── TA=0x0002 → 7E0/7E8 → 项目一的 ECU（VIN=LSVAA0000A1234567）
#                              └── TA=0x0003 → 7A0/7A8 → stub-ecu（VIN=LSVZZ0000B7654321, HW02）
#                              TA=0x0004 → 表里没有 → 0x8003 0x03
#
# 依赖（缺了就 SKIP，不算红）：
#   vcan0、~/uds-ecu/build/uds-demo、python3 + doipclient、./build/stub-ecu
#
# 用法： bash tools/m6_e2e.sh [端口]     默认端口 13461
# =============================================================================
set -u

PORT=${1:-13461}
IFACE=${IFACE:-vcan0}
ECU_A=${ECU_A:-$HOME/uds-ecu/build/uds-demo}
HERE=$(cd "$(dirname "$0")" && pwd)
GW=$HERE/../build/doip-gateway
ECU_B=$HERE/../build/stub-ecu
PY=${PY:-python3}

VIN_A=LSVAA0000A1234567
VIN_B=LSVZZ0000B7654321

pass=0; fail=0
ok()  { echo "[PASS] $1"; pass=$((pass+1)); }
bad() { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
  pkill -x doip-gateway 2>/dev/null
  pkill -x stub-ecu 2>/dev/null
  pkill -x uds-demo 2>/dev/null
}
trap cleanup EXIT

# ---- 0. 依赖 ----
[ -e /sys/class/net/$IFACE ] || { skip "没有 $IFACE（先 bash ~/uds-ecu/tools/vcanup.sh）"; exit 0; }
[ -x "$ECU_A" ] || { skip "没有项目一的 $ECU_A"; exit 0; }
[ -x "$GW" ]    || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
[ -x "$ECU_B" ] || { skip "没有 $ECU_B（先 cmake --build build）"; exit 0; }
$PY -c 'import doipclient' 2>/dev/null || { skip "没装第三方客户端（pip3 install --user doipclient）"; exit 0; }

cleanup
echo "=== 起两台 ECU + 一个网关 ==="
"$ECU_A" --ecu --iface "$IFACE" --wait-s 45 > /tmp/m6_a.log 2>&1 &
A_PID=$!
stdbuf -oL "$ECU_B" --iface "$IFACE" --rx 7A0 --tx 7A8 --vin "$VIN_B" --hw HW02 --seconds 40 \
    > /tmp/m6_b.log 2>&1 &
B_PID=$!
sleep 1
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 36 \
    --route 0002:7E0:7E8:ECU_A --route 0003:7A0:7A8:ECU_B > /tmp/m6_gw.log 2>&1 &
GW_PID=$!
sleep 1.5

echo
echo "=== 1/7 路由表长得什么样 ==="
grep -A3 '路由表' /tmp/m6_gw.log | sed 's/^/      /'
grep -q 'TA=0x0002 → 0x7E0 / 0x7E8' /tmp/m6_gw.log && ok "表里有 TA=2 → 0x7E0/0x7E8" || bad "路由表里没有 TA=2"
grep -q 'TA=0x0003 → 0x7A0 / 0x7A8' /tmp/m6_gw.log && ok "表里有 TA=3 → 0x7A0/0x7A8" || bad "路由表里没有 TA=3"

echo
echo "=== 2/7 TA=0x0002 → 项目一的 ECU（读 VIN）==="
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0002 --uds "22 F1 90" --vin "$VIN_A" > /tmp/m6_r2.log 2>&1
grep -E '请求|VIN|PASS|FAIL' /tmp/m6_r2.log | sed 's/^/      /'
grep -q "VIN=$VIN_A" /tmp/m6_r2.log && ok "TA=2 读到 ECU_A 的 VIN" || bad "TA=2 没读到 ECU_A 的 VIN"

echo
echo "=== 3/7 TA=0x0003 → stub-ecu（同一个 DID，不同的值）==="
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0003 --uds "22 F1 90" --vin "$VIN_B" > /tmp/m6_r3.log 2>&1
grep -E '请求|VIN|PASS|FAIL' /tmp/m6_r3.log | sed 's/^/      /'
grep -q "VIN=$VIN_B" /tmp/m6_r3.log && ok "TA=3 读到 ECU_B 的 VIN（和 TA=2 不同的值）" || bad "TA=3 没读到 ECU_B 的 VIN"

echo
echo "=== 4/7 TA=0x0003 读硬件版本（证明服务在 B 上也是真的）==="
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0003 --uds "22 F1 91" --expect "62 F1 91 48 57 30 32" > /tmp/m6_r4.log 2>&1
grep -E '请求|PASS|FAIL' /tmp/m6_r4.log | sed 's/^/      /'
grep -q 'RESP_HEX=62 F1 91 48 57 30 32' /tmp/m6_r4.log && ok "TA=3 读到 HW02" || bad "TA=3 读 HW 失败"

echo
echo "=== 5/7 TA=0x0004（表里没有）→ 必须 0x8003 0x03 ==="
$PY "$HERE/m5_check.py" unknown --port "$PORT" --sa 0x0E00 --ta 0x0004 > /tmp/m6_r5.log 2>&1
grep -E 'PASS|FAIL|负应答' /tmp/m6_r5.log | sed 's/^/      /'
grep -q 'NACK 码 0x03' /tmp/m6_r5.log && ok "不存在的地址被明确拒绝（0x03）" || bad "未知地址没被拒成 0x03"

echo
echo "=== 6/7 两个客户端并发，一个打 A 一个打 B（不许串）==="
$PY "$HERE/m5_check.py" concurrent --port "$PORT" \
    --ta 0x0002 --uds "22 F1 90" --expect "62 F1 90" \
    --ta2 0x0003 --uds2 "22 F1 91" --expect2 "62 F1 91" --rounds 3 > /tmp/m6_r6.log 2>&1
grep -E 'PASS|FAIL|最后一条' /tmp/m6_r6.log | sed 's/^/      /'
grep -q '\[PASS\] B 的每条响应都以 62 F1 91 开头' /tmp/m6_r6.log && ok "并发下 B 只拿到 B 的响应" || bad "并发串了"

echo
echo "=== 7/7 停在网关的账上，等它自己跑完 ==="
wait $GW_PID 2>/dev/null
sed -n '/以太网侧/,$p' /tmp/m6_gw.log | sed 's/^/      /'
grep -q 'TA=0x0002' /tmp/m6_gw.log && ok "网关按路由分别记账" || true
grep -q '转发 9 条，失败 0 条' /tmp/m6_gw.log && ok "总共转发 9 条、0 失败" || bad "转发统计不符"
kill $A_PID $B_PID 2>/dev/null

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] || exit 1
