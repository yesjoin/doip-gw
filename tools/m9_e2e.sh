#!/usr/bin/env bash
# =============================================================================
# m9_e2e.sh —— M9 验收：CAN FD（同一套 ISO-TP，换个 64 字节的信封）
#
# 用法： bash tools/m9_e2e.sh [端口]      默认 13465
#
# 为什么这么设计：
#   FD 的坑不在"能不能发 64 字节"，而在**分片规则整片移动**之后还剩不剩对的：
#     单帧边界 7 → 62（8..62 必须用转义单帧 0x00 + 长度）
#     首帧载荷 6 → 62，连续帧载荷 7 → 63
#   只要有一处还按 8 字节算，现场表现就两种："长度不对"或者"卡在第 2 帧"。
#   所以本脚本不用"能收到就算过"，而是**两个通道对同一个 DID**：
#     内容必须逐字节相同（证明协议没走样）
#     帧数必须各自对上（证明信封真的换了）
#
# 拓扑（同一条 vcan0，一张表里经典和 FD 混着挂）：
#   ECU_C （经典帧）TA=0x0003 → 7A0 / 7A8        VIN LSVZZ0000B7654321  HW02
#   ECU_FD（CAN FD）TA=0x0006 → 18DA00F1/18DAF100 VIN LSVCC0000C7654321  HW03
#
# 期望帧数（都是手算出来的，脚本只是核对）：
#   DID 响应总长   FD 帧数   经典帧数
#   0xF1A0  62      1（转义单帧）  9（FF + 8 CF）
#   0xF1A2 200      4（FF+3 CF）   29（FF + 28 CF）
#   0xF190  20      1（转义单帧）  3（FF + 2 CF）
# =============================================================================
set -u

PORT=${1:-13465}
IFACE=${IFACE:-vcan0}
GW=$(cd "$(dirname "$0")/.." && pwd)/build/doip-gateway
STUB=$(cd "$(dirname "$0")/.." && pwd)/build/stub-ecu
PY=${PY:-python3}
HERE=$(cd "$(dirname "$0")" && pwd)
CANLOG=/tmp/m9_can.log

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

# FD 帧 72 字节，vcan 的 MTU 必须 >= 72，否则内核直接拒收
MTU=$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null || echo 0)
[ "$MTU" -ge 72 ] || { skip "$IFACE 的 MTU=$MTU < 72，发不了 FD（sudo ip link set $IFACE mtu 72）"; exit 0; }
ok "vcan0 的 MTU=$MTU，装得下 FD 帧（72 字节）"

cleanup
echo "=== 起一台经典 ECU + 一台 FD ECU + 网关（一张路由表两种信封）+ 总线录制 ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 60 > /tmp/m9_c.log 2>&1 &
stdbuf -oL "$STUB" --iface "$IFACE" --fd --rx 18DA00F1 --tx 18DAF100 \
        --vin LSVCC0000C7654321 --hw HW03 --seconds 60 > /tmp/m9_fd.log 2>&1 &
candump -L "$IFACE" > "$CANLOG" 2>&1 &
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 50 \
    --route 0003:7A0:7A8:ECU_C \
    --route 0006:18DA00F1:18DAF100:ECU_FD:fd > /tmp/m9_gw.log 2>&1 &

for i in $(seq 1 40); do
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&-; break; }
    sleep 0.2
done
sleep 1

# ---- 工具函数 ----
snap()  { wc -l < "$CANLOG"; }
since() { tail -n +$(( $1 + 1 )) "$CANLOG"; }
# FD 帧在 candump -L 里是双井号：id##<flags><data>，扣掉 1 位 flags 就是数据长度
fdlen() { since "$1" | grep -- "$2##" | awk -F'##' '{ s=$2; sub(/^[0-9A-Fa-f]/, "", s); print length(s)/2 }' | sort -u | tr '\n' ' '; }

# 读一个 DID，只回 RESP_HEX（其余日志丢掉）
read_did() { "$PY" "$HERE/m5_check.py" read --host 127.0.0.1 --port "$PORT" \
                 --ta "$1" --uds "$2" 2>&1 | sed -n 's/^RESP_HEX=//p'; }

# 期望的响应正文（3 字节头 + 下标 & 0xFF）
EXP_200=$($PY -c 'print(" ".join("%02X" % b for b in [0x62,0xF1,0xA2] + [i & 0xFF for i in range(197)]))')
EXP_62=$($PY -c 'print(" ".join("%02X" % b for b in [0x62,0xF1,0xA0] + [i & 0xFF for i in range(59)]))')

# ---- 1. 启动状态 ----
echo
echo "=== 1 启动：一张表里两种信封 ==="
grep -q "（FD，帧长 64）" /tmp/m9_gw.log \
    && ok "网关的路由表里，TA=0x0006 标成 FD（帧长 64）" \
    || bad "网关没把 TA=0x0006 标成 FD"
grep -q "CAN FD（帧长 64" /tmp/m9_fd.log \
    && ok "FD 那台 ECU 自己也按 64 字节说话" \
    || bad "FD ECU 的启动行不对"
grep -q "经典 CAN（帧长 8" /tmp/m9_c.log \
    && ok "经典那台 ECU 还是 8 字节（同一条总线两种帧长并存）" \
    || bad "经典 ECU 的启动行不对"

# ---- 2. FD：200 字节 ----
echo
echo "=== 2 FD 通道读 0xF1A2（200 字节）==="
m=$(snap); got=$(read_did 0x0006 "22 F1 A2")
[ -n "$got" ] && ok "FD 通道收到响应（$(echo "$got" | wc -w) 字节）" || bad "FD 通道没收到响应"
[ "$got" = "$EXP_200" ] && ok "FD 下 200 字节逐字节正确（62 F1 A2 00 01 02 …）" || bad "FD 下内容不对"
sleep 1
n=$(since "$m" | grep -c -- "18DAF100##")
[ "$n" -eq 4 ] && ok "抓包：FD 应答恰好 4 帧（首帧 + 3 张连续帧）" || bad "抓包：FD 应答 $n 帧，期望 4"
lens=$(fdlen "$m" "18DAF100")
[ "$lens" = "64 " ] && ok "抓包：每张 FD 帧都写满 64 字节" || bad "抓包：FD 帧长度是 [$lens]，期望 64"

# ---- 3. 经典：同一个 DID ----
echo
echo "=== 3 经典通道读同一个 DID（内容要一样，帧数要多得多）==="
m=$(snap); got=$(read_did 0x0003 "22 F1 A2")
[ "$got" = "$EXP_200" ] && ok "经典帧下 200 字节与 FD 逐字节相同（协议没走样，只是信封变小）" || bad "经典帧下内容不对"
sleep 1
n=$(since "$m" | grep -c -- "7A8#")
[ "$n" -eq 29 ] && ok "抓包：经典应答 29 帧（首帧 + 28 张连续帧）" || bad "抓包：经典应答 $n 帧，期望 29"

# ---- 4. 边界：62 字节（正好卡在 FD 单帧上限）----
echo
echo "=== 4 边界 0xF1A0（62 字节：FD 一张单帧装完，经典要 9 帧）==="
m=$(snap); got=$(read_did 0x0006 "22 F1 A0")
[ "$got" = "$EXP_62" ] && ok "FD 下 62 字节内容正确" || bad "FD 下 62 字节内容不对"
sleep 1
n=$(since "$m" | grep -c -- "18DAF100##")
[ "$n" -eq 1 ] && ok "抓包：FD 下 62 字节只发 1 帧（转义单帧 0x00 0x3E …）" || bad "抓包：FD 下 62 字节发了 $n 帧，期望 1"
m=$(snap); got=$(read_did 0x0003 "22 F1 A0")
[ "$got" = "$EXP_62" ] && ok "经典帧下 62 字节内容相同" || bad "经典帧下 62 字节内容不对"
sleep 1
n=$(since "$m" | grep -c -- "7A8#")
[ "$n" -eq 9 ] && ok "抓包：经典帧下 62 字节要 9 帧（多出 1 帧就跨过单帧边界）" || bad "抓包：经典帧下 62 字节发了 $n 帧，期望 9"

# ---- 5. VIN（20 字节，两种信封都能单帧 vs 三帧）----
echo
echo "=== 5 VIN（20 字节：FD 单帧，经典 FF + 2 CF）==="
m=$(snap); got=$(read_did 0x0006 "22 F1 90")
$PY -c "import sys; s='$got'.replace(' ',''); sys.exit(0 if bytes.fromhex(s)[3:20]==b'LSVCC0000C7654321' else 1)" \
    && ok "FD 下 VIN = LSVCC0000C7654321" || bad "FD 下 VIN 不对"
sleep 1
n=$(since "$m" | grep -c -- "18DAF100##")
[ "$n" -eq 1 ] && ok "抓包：FD 下 VIN 只用 1 帧（20 字节塞进转义单帧）" || bad "抓包：FD 下 VIN 发了 $n 帧，期望 1"
m=$(snap); got=$(read_did 0x0003 "22 F1 90")
$PY -c "import sys; s='$got'.replace(' ',''); sys.exit(0 if bytes.fromhex(s)[3:20]==b'LSVZZ0000B7654321' else 1)" \
    && ok "经典帧下 VIN = LSVZZ0000B7654321" || bad "经典帧下 VIN 不对"
sleep 1
n=$(since "$m" | grep -c -- "7A8#")
[ "$n" -eq 3 ] && ok "抓包：经典帧下 VIN 要 3 帧（首帧装 6 字节，剩下 14 字节分两张 CF）" || bad "抓包：经典帧下 VIN 发了 $n 帧，期望 3"

# ---- 6. 网关账 ----
echo
echo "=== 6 网关自己的账 ==="
grep -qE "回来 .* 条|下游答了" /tmp/m9_gw.log && ok "网关每条请求都记了应答条数" || bad "网关没有应答记录"
if grep -q "下游拒绝\|超时" /tmp/m9_gw.log; then
    bad "网关日志里有失败记录（$(grep -c "下游拒绝\|超时" /tmp/m9_gw.log) 处）"
else
    ok "网关日志里没有任何失败记录"
fi

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M9 全绿 —— 同一套 ISO-TP：FD 用 4 帧送走的 200 字节，经典帧要 29 帧。"
    echo "换句话说，改的不是协议，是信封；信封一变，分片规则整片跟着变，两处必须同时对上。"
fi
exit $(( fail == 0 ? 0 : 1 ))
