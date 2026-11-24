#!/usr/bin/env bash
# =============================================================================
# m8_e2e.sh —— M8 验收：功能寻址（一条请求，几台 ECU 一起答）
#
# 用法： bash tools/m8_e2e.sh [端口]      默认 13462
#
# 为什么这么设计：
#   功能寻址的坑不在"能不能往 7DF 发一帧"，而在**收**：
#   一条广播出去，答案条数不由网关决定，由"谁在听"决定。
#   所以本脚本盯三件事：
#     ① 两台 ECU 同一个 DID 各回一句，**SA 必须不一样**（谁答的要说清）
#     ② 响应塞不进单帧时，ECU 不能装能答（读 VIN 在功能寻址上就是没有答案）
#     ③ 广播之后物理寻址还得照常工作（别为了广播把通道弄脏）
#
# 拓扑（同一条 vcan0）：
#   ECU_B（stub-ecu 7A0/7A8，听 7DF）         TA=0x0003，VIN LSVZZ0000B7654321，HW02
#   ECU_C（stub-ecu 18DA00F1/18DAF100，听 7DF） TA=0x0006，VIN LSVCC0000C7654321，HW03
#   功能地址 0xE400 → 广播 0x7DF
# =============================================================================
set -u

PORT=${1:-13462}
IFACE=${IFACE:-vcan0}
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
    pkill -x candump 2>/dev/null
    true
}
trap cleanup EXIT

# ---- 0. 依赖 ----
[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE（先 bash ~/uds-ecu/tools/vcanup.sh）"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB（先 cmake --build build）"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW"; exit 0; }
command -v candump >/dev/null 2>&1 || { skip "没有 candump（can-utils）"; exit 0; }
$PY -c 'import doipclient' 2>/dev/null || { skip "没装 doipclient（pip3 install --user doipclient）"; exit 0; }

cleanup
echo "=== 起两台都会听广播的 ECU + 网关 + 总线录制 ==="
# 两台都听 7DF：这是功能寻址在 ECU 侧的全部要求（多开一个耳朵）
"$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 --func-rx 7DF \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 40 > /tmp/m8_b.log 2>&1 &
"$STUB" --iface "$IFACE" --rx 18DA00F1 --tx 18DAF100 --func-rx 7DF \
        --vin LSVCC0000C7654321 --hw HW03 --seconds 40 > /tmp/m8_c.log 2>&1 &
candump -L "$IFACE" > /tmp/m8_can.log 2>&1 &
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 34 \
    --route 0003:7A0:7A8:ECU_B \
    --route 0006:18DA00F1:18DAF100:ECU_EXT \
    --func 0xE400:0x7DF:ALL > /tmp/m8_gw.log 2>&1 &
GW_PID=$!
sleep 2

# ---- 1. 路由表：物理两条 + 功能一条，一眼分得清 ----
echo
echo "=== 1/8 启动时打印的两张表 ==="
grep -A2 '路由表' /tmp/m8_gw.log | sed 's/^/      /'
grep -A2 '功能路由' /tmp/m8_gw.log | sed 's/^/      /'
grep -q 'TA=0xE400 → 0x7DF' /tmp/m8_gw.log && ok "功能路由打出来了（0xE400 → 0x7DF，注明是广播）" || bad "日志里没有功能路由"
grep -q 'TA=0x0003 → 0x7A0 / 0x7A8' /tmp/m8_gw.log && ok "物理路由还在（功能寻址是加一条广播，不是把物理路由换掉）" || bad "物理路由不见了"

# ---- 2. 一次广播，两台 ECU 各答一句：SA 必须不一样 ----
echo
echo "=== 2/8 功能寻址读硬件版本（22 F1 91）→ 应该回来 2 条 ==="
$PY "$HERE/m5_check.py" func --port "$PORT" --sa 0x0E00 --ta 0xE400 \
    --uds "22 F1 91" --count 2 --sas 0x0003,0x0006 --expect "62 F1 91" \
    | tee /tmp/m8_hw.log | sed 's/^/      /'
grep -q 'RESP0_HEX=62 F1 91 48 57 30 32\|RESP1_HEX=62 F1 91 48 57 30 32' /tmp/m8_hw.log \
    && ok "ECU_B 答了 HW02（62 F1 91 48 57 30 32）" || bad "没看到 ECU_B 的 HW02"
grep -q 'RESP0_HEX=62 F1 91 48 57 30 33\|RESP1_HEX=62 F1 91 48 57 30 33' /tmp/m8_hw.log \
    && ok "ECU_C 答了 HW03（62 F1 91 48 57 30 33）" || bad "没看到 ECU_C 的 HW03"

# ---- 3. 换个服务再来一次（别只有一个服务碰巧通）----
echo
echo "=== 3/8 功能寻址 3E 00 → 两台都应 7E 00 ==="
$PY "$HERE/m5_check.py" func --port "$PORT" --sa 0x0E00 --ta 0xE400 \
    --uds "3E 00" --count 2 --sas 0x0003,0x0006 --expect "7E 00" \
    | tee /tmp/m8_tp.log | sed 's/^/      /'
grep -q '\[PASS\]' /tmp/m8_tp.log && ok "3E 00 广播：两台都答 7E 00" || bad "3E 00 广播失败"

# ---- 4. 响应塞不进单帧 → 谁也不许答（读 VIN 就是这种情况）----
echo
echo "=== 4/8 功能寻址读 VIN（响应 20 字节，塞不进单帧）==="
$PY "$HERE/m5_check.py" func --port "$PORT" --sa 0x0E00 --ta 0xE400 \
    --uds "22 F1 90" --count 0 --nack 0x06 \
    | tee /tmp/m8_vin.log | sed 's/^/      /'
grep -q 'NACK_CODE=0x06' /tmp/m8_vin.log \
    && ok "没人答 → 0x8003 0x06（目标存在但不可达，不是 0x03 地址不认识）" \
    || bad "读 VIN 的功能寻址没有按预期回 0x06"

# ---- 5. 请求超过 7 字节：协议上做不到，必须当场拒 ----
echo
echo "=== 5/8 功能寻址发 8 字节请求 ==="
$PY "$HERE/m5_check.py" func --port "$PORT" --sa 0x0E00 --ta 0xE400 \
    --uds "2E F1 90 01 02 03 04 05" --count 0 --nack 0x04 \
    | tee /tmp/m8_long.log | sed 's/^/      /'
grep -q 'NACK_CODE=0x04' /tmp/m8_long.log \
    && ok "8 字节 → 0x8003 0x04（报文太大：功能寻址只能单帧）" \
    || bad "超过 7 字节没有被 0x04 拒"

# ---- 6. 广播之后，物理寻址必须照常工作 ----
echo
echo "=== 6/8 广播玩完了，物理地址还认不认人 ==="
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0003 --uds "22 F1 90" --vin LSVZZ0000B7654321 \
    | tee /tmp/m8_phys_b.log | sed 's/^/      /'
grep -q 'VIN=LSVZZ0000B7654321' /tmp/m8_phys_b.log && ok "物理 TA=0x0003 读 VIN 正常（通道没被广播搞脏）" || bad "广播之后物理寻址坏了"
$PY "$HERE/m5_check.py" read --port "$PORT" --ta 0x0006 --uds "22 F1 90" --vin LSVCC0000C7654321 \
    | tee /tmp/m8_phys_c.log | sed 's/^/      /'
grep -q 'VIN=LSVCC0000C7654321' /tmp/m8_phys_c.log && ok "物理 TA=0x0006（29 位）读 VIN 也正常" || bad "29 位通道被广播影响"

# ---- 7. 总线侧取证：7DF 只该出现 3 次（发了 3 次广播，不是每台 ECU 发一遍）----
echo
echo "=== 7/8 总线侧取证 ==="
sleep 1
BCAST=$(grep -c ' 7DF#' /tmp/m8_can.log)
echo "      总线上的 7DF 帧数：$BCAST（期望 3：2、3、4 步各广播一次；第 5 步在发之前就被拒了）"
[ "$BCAST" = "3" ] && ok "广播只发了 3 帧（不是 N 台 ECU 各发一遍）" || bad "广播帧数不对（$BCAST）"
grep -q ' 7A8#' /tmp/m8_can.log && ok "ECU_B 的应答（7A8）在总线上" || bad "总线上没有 7A8"
grep -q ' 18DAF100#' /tmp/m8_can.log && ok "ECU_C 的应答（18DAF100，8 位）也在" || bad "总线上没有 18DAF100"
echo "      总线样本（前 8 行）："
head -8 /tmp/m8_can.log | sed 's/^/        /'

# ---- 8. 等网关收工，看它的账 ----
echo
echo "=== 8/8 网关的账 ==="
wait $GW_PID 2>/dev/null
sed -n '/CAN 侧/,$p' /tmp/m8_gw.log | sed 's/^/      /'
grep -q '广播 3 次' /tmp/m8_gw.log && ok "广播次数记对了（3 次）" || bad "广播次数没记对"
grep -q '收回应答 4 条' /tmp/m8_gw.log && ok "收回应答 4 条（2 台 × 2 次有效广播；读 VIN 那次无人应答）" || bad "应答条数没记对"
grep -q '无人应答 1 次' /tmp/m8_gw.log && ok "无人应答单独计数（1 次）—— 和失败分开记，错因不同" || bad "无人应答次数没记对"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ] || exit 1
