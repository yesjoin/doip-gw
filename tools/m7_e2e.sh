#!/usr/bin/env bash
# =============================================================================
# m7_e2e.sh —— M7 验收：一条总线上同时跑"11 位 ECU"和"29 位 ECU"
#
# 用法： bash tools/m7_e2e.sh [端口]      默认 13462
#
# 为什么这么设计：
#   29 位 ID 的坑不在"能不能算出一个大数字"，而在**发帧时那个标志位**。
#   只要漏了 CAN_EFF_FLAG，内核就回 EINVAL，帧根本没上总线——candump 一片空白，
#   而网关只会报"超时"。所以本脚本除了看响应值，还要从**总线侧**取证：
#   用 candump 抓一遍，确认 18DAF100 这种 8 位 ID 真的出现在总线上。
#
# 拓扑：
#   ECU_A（项目一 uds-demo，标准帧 7E0/7E8）      TA=0x0002
#   ECU_B（stub-ecu，扩展帧 18DA00F1/18DAF100）   TA=0x0006
# =============================================================================
set -u

PORT=${1:-13462}
IFACE=${IFACE:-vcan0}
ECU=${ECU:-$HOME/uds-ecu/build/uds-demo}
GW=$(cd "$(dirname "$0")/.." && pwd)/build/doip-gateway
STUB=$(cd "$(dirname "$0")/.." && pwd)/build/stub-ecu
PY=${PY:-python3}
HERE=$(cd "$(dirname "$0")" && pwd)

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    pkill -x uds-demo 2>/dev/null
    pkill -x candump 2>/dev/null
}
trap cleanup EXIT

# ---- 0. 依赖 ----
[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE（先 bash ~/uds-ecu/tools/vcanup.sh）"; exit 0; }
[ -x "$ECU" ]  || { skip "没有项目一的 $ECU"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB（先 cmake --build build）"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW"; exit 0; }
command -v candump >/dev/null 2>&1 || { skip "没有 candump（can-utils）"; exit 0; }
$PY -c 'import doipclient' 2>/dev/null || { skip "没装 doipclient（pip3 install --user doipclient）"; exit 0; }

cleanup
echo "=== 起两台 ECU（一台标准帧、一台扩展帧）+ 网关 + 总线录制 ==="
"$ECU"  --ecu --iface "$IFACE" --wait-s 45 > /tmp/m7_ecu.log 2>&1 &
"$STUB" --iface "$IFACE" --rx 18DA00F1 --tx 18DAF100 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 40 > /tmp/m7_stub.log 2>&1 &
candump -L "$IFACE" > /tmp/m7_can.log 2>&1 &
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 34 \
    --route 0002:7E0:7E8:ECU_A \
    --route 0006:18DA00F1:18DAF100:ECU_EXT > /tmp/m7_gw.log 2>&1 &
GW_PID=$!
sleep 2

# ---- 1. 路由表打印：宽度一眼看得出来 ----
echo
echo "=== 1/6 启动时打印的路由表 ==="
grep -q '0x7E0' /tmp/m7_gw.log && ok "标准帧那条打出来了（0x7E0）" || bad "日志里没有 0x7E0"
grep -q '0x18DAF100' /tmp/m7_gw.log && ok "扩展帧那条打出来了（0x18DAF100，8 位）" || bad "日志里没有 0x18DAF100"

# ---- 2. 标准帧照常工作：别为了 29 位把 11 位弄坏 ----
echo
echo "=== 2/6 TA=0x0002（标准帧 7E0/7E8）读 VIN ==="
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0002 --uds "22 F1 90" --vin LSVAA0000A1234567 \
    | tee /tmp/m7_vin_a.log | sed 's/^/      /'
grep -q 'VIN=LSVAA0000A1234567' /tmp/m7_vin_a.log && ok "标准帧读到 ECU_A 的 VIN" || bad "标准帧读 VIN 失败"

# ---- 3. 扩展帧：同一件事，换 29 位 ID ----
echo
echo "=== 3/6 TA=0x0006（扩展帧 18DA00F1/18DAF100）读 VIN ==="
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0006 --uds "22 F1 90" --vin LSVZZ0000B7654321 \
    | tee /tmp/m7_vin_b.log | sed 's/^/      /'
grep -q 'VIN=LSVZZ0000B7654321' /tmp/m7_vin_b.log && ok "扩展帧读到 ECU_B 的 VIN（值不同，说明真的打到了另一台）" || bad "扩展帧读 VIN 失败"

# ---- 4. 扩展帧上的另一个服务也要通（不是只有一条 DID 碰巧过了）----
echo
echo "=== 4/6 TA=0x0006 读硬件版本（22 F1 91） ==="
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0006 --uds "22 F1 91" --expect "62 F1 91 48 57 30 32" \
    | tee /tmp/m7_hw.log | sed 's/^/      /'
grep -q '\[PASS\]' /tmp/m7_hw.log && ok "扩展帧上 22 F1 91 也对（62 F1 91 48 57 30 32）" || bad "扩展帧读 HW 失败"

# ---- 5. 总线侧取证：candump 里必须真的出现 8 位 ID ----
echo
echo "=== 5/6 总线侧取证：candump 抓到的是不是真的扩展帧 ==="
sleep 1
if grep -q '18DAF100' /tmp/m7_can.log; then
    ok "总线上出现了 18DAF100（8 位 = 扩展帧，说明 CAN_EFF_FLAG 置对了）"
else
    bad "总线上没有 18DAF100（CAN_EFF_FLAG 没置，帧根本没出去）"
fi
if grep -q '7E8' /tmp/m7_can.log; then
    ok "总线上同时也有 7E8（标准帧那条没被 29 位逻辑影响）"
else
    bad "总线上没抓到 7E8"
fi
echo "      总线样本（前 6 行）："
head -6 /tmp/m7_can.log | sed 's/^/        /'

# ---- 6. 等网关收工，看它自己的账（两条通道分开记）----
echo
echo "=== 6/6 网关的账 ==="
wait $GW_PID 2>/dev/null
sed -n '/CAN 侧/,$p' /tmp/m7_gw.log | sed 's/^/      /'
grep -q 'TA=0x0002（0x7E0/0x7E8）'      /tmp/m7_gw.log && ok "标准帧通道单独记账" || bad "没看到标准帧通道的账"
grep -q 'TA=0x0006（0x18DA00F1/0x18DAF100）' /tmp/m7_gw.log && ok "扩展帧通道单独记账（8 位 ID）" || bad "没看到扩展帧通道的账"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] || exit 1
