#!/usr/bin/env bash
# =============================================================================
# m5_e2e.sh —— M5 验收：第三方客户端 → 网关 → 项目一 ECU，一条命令跑完 5 条硬指标
#
# 依赖（缺了就 SKIP，不算红）：
#   vcan0、~/uds-ecu/build/uds-demo、python3 + `doipclient`（pip3 install --user doipclient）
#
# 用法： bash tools/m5_e2e.sh [端口]     默认端口 13458
# =============================================================================
set -u

PORT=${1:-13458}
IFACE=${IFACE:-vcan0}
ECU=${ECU:-$HOME/uds-ecu/build/uds-demo}
GW=$(cd "$(dirname "$0")/.." && pwd)/build/doip-gateway
PY=${PY:-python3}
HERE=$(cd "$(dirname "$0")" && pwd)

pass=0; fail=0
ok()  { echo "[PASS] $1"; pass=$((pass+1)); }
bad() { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
  pkill -x doip-gateway 2>/dev/null
  pkill -x uds-demo 2>/dev/null
}
trap cleanup EXIT

# ---- 0. 依赖检查 ----
[ -e /sys/class/net/$IFACE ] || { skip "没有 $IFACE（先 bash ~/uds-ecu/tools/vcanup.sh）"; exit 0; }
[ -x "$ECU" ] || { skip "没有项目一的 $ECU"; exit 0; }
[ -x "$GW" ]  || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
$PY -c 'import doipclient' 2>/dev/null || { skip "没装第三方客户端（pip3 install --user doipclient）"; exit 0; }

cleanup
echo "=== 起 ECU（项目一，真 CAN 侧）和网关（以太网侧）==="
"$ECU" --ecu --iface "$IFACE" --wait-s 60 > /tmp/m5_ecu.log 2>&1 &
ECU_PID=$!
# stdbuf -oL：不缓冲，日志才能边跑边看（不然进程被杀时一个字都看不到）
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 18 > /tmp/m5_gw.log 2>&1 &
GW_PID=$!
sleep 1.5

# ---- 1. 第三方客户端发现（UDP）----
echo
echo "=== 1/6 第三方客户端做车辆发现（UDP $PORT）==="
$PY "$HERE/m5_check.py" discover --host 127.0.0.1 --port "$PORT" | tee /tmp/m5_disc.log
if grep -q '\[PASS\] VIN 是 17 位' /tmp/m5_disc.log; then ok "第三方客户端能发现实体"; else bad "发现失败"; fi

# ---- 2. 第三方客户端读 VIN（验收第 1 条）----
echo
echo "=== 2/6 第三方客户端 22 F1 90（验收第 1 条）==="
$PY "$HERE/m5_check.py" read --host 127.0.0.1 --port "$PORT" --ta 0x0001 --uds "22 F1 90" | tee /tmp/m5_vin.log
if grep -q 'VIN=' /tmp/m5_vin.log; then ok "第三方客户端读到 VIN"; else bad "读 VIN 失败"; fi

# ---- 3. CAN 直读同一 DID（验收第 2 条：两边必须一样）----
echo
echo "=== 3/6 CAN 直读同一个 DID，和 DoIP 侧对值（验收第 2 条）==="
"$ECU" --tester "22 F1 90" --iface "$IFACE" --wait-s 3 > /tmp/m5_can.log 2>&1
CAN_HEX=$(grep -oE '响应 \([0-9]+ 字节\): [0-9A-F ]+' /tmp/m5_can.log | sed 's/.*: //; s/ *$//')
DOIP_HEX=$(grep -oE 'RESP_HEX=.*' /tmp/m5_vin.log | sed 's/RESP_HEX=//')
echo "       CAN 直读：$CAN_HEX"
echo "       DoIP 侧 ：$DOIP_HEX"
if [ -n "$CAN_HEX" ] && [ "$CAN_HEX" = "$DOIP_HEX" ]; then ok "同一 DID 两侧逐字节一致"; else bad "两侧不一致"; fi

# ---- 4. 40+ 字节请求穿过网关（验收第 3 条）----
echo
echo "=== 4/6 47 字节请求穿过网关（CAN 侧必须自动多帧，验收第 3 条）==="
REQ47="2E F1 90"
for _ in $(seq 1 44); do REQ47="$REQ47 00"; done
$PY "$HERE/m5_check.py" read --host 127.0.0.1 --port "$PORT" --ta 0x0001 --uds "$REQ47" > /tmp/m5_long.log 2>&1
grep -E '请求|响应' /tmp/m5_long.log | head -2
if grep -q 'RESP_HEX=7F' /tmp/m5_long.log; then ok "47 字节请求到 ECU，ECU 回负响应（说明整条多帧链路通）"; else bad "长请求失败"; fi

# ---- 5. 未激活就发诊断（验收第 5 条）----
echo
echo "=== 5/6 新连接不激活直接发诊断（验收第 5 条：不许记住上次）==="
$PY "$HERE/m5_check.py" noact --host 127.0.0.1 --port "$PORT" --sa 0x0E00 --ta 0x0001 | tee /tmp/m5_noact.log
if grep -q '\[PASS\] NACK 码 0x02' /tmp/m5_noact.log; then ok "未激活被明确拒绝（0x8003 / 0x02）"; else bad "未激活没被拒绝"; fi

# ---- 6. 两个第三方客户端并发（验收第 4 条）----
echo
echo "=== 6/6 两个第三方客户端并发，不许串包（验收第 4 条）==="
$PY "$HERE/m5_check.py" concurrent --host 127.0.0.1 --port "$PORT" --ta 0x0001 --rounds 2 | tee /tmp/m5_conc.log
if grep -q '\[PASS\] B 的每条响应都以 7E 00' /tmp/m5_conc.log; then ok "并发不串包"; else bad "并发串包"; fi

# ---- 汇总 ----
echo
echo "=== 网关自己的账（等它自己跑完 18 秒，才好打汇总）==="
wait $GW_PID 2>/dev/null
sed -n '/以太网侧/,$p' /tmp/m5_gw.log
kill $ECU_PID 2>/dev/null

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] || exit 1
