#!/usr/bin/env bash
# =============================================================================
# m10_e2e.sh —— M10 验收：多 tester 各自独立通道（每条通道一条队列 + 一条线程）
#
# 用法： bash tools/m10_e2e.sh [端口]      默认 13466
#
# 这一步要证明的不是"能同时连两个客户端"（M5 就能），而是：
#   ① 两条不同通道**真的并行**：一台慢，另一台不等它
#   ② 同一条通道**必须串行**：两个 tester 抢同一台 ECU，响应不许交叉
#   ③ 同一条连接**不许有第二条在途**：连发两条，第二条当场拒（没有流水线语义）
#   ④ 连接断了，在途请求**作废**：结果回来也不许转给下一个诊断仪
#   ⑤ 压力下账要能对上：转发条数 = 请求条数，失败 0
#
# 拓扑（同一条 vcan0）：
#   ECU_C   TA=0x0003  7A0/7A8            经典帧，快
#   ECU_FD  TA=0x0006  18DA00F1/18DAF100  FD 64，快
#   ECU_SL  TA=0x0007  7B0/7B8            经典帧，**每条应答前睡 700ms**
# =============================================================================
set -u

PORT=${1:-13466}
IFACE=${IFACE:-vcan0}
GW=$(cd "$(dirname "$0")/.." && pwd)/build/doip-gateway
STUB=$(cd "$(dirname "$0")/.." && pwd)/build/stub-ecu
PY=${PY:-python3}
HERE=$(cd "$(dirname "$0")" && pwd)
CANLOG=/tmp/m10_can.log
GWLOG=/tmp/m10_gw.log

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

[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB（先 cmake --build build）"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW"; exit 0; }
command -v candump >/dev/null 2>&1 || { skip "没有 candump"; exit 0; }
$PY -c 'import doipclient' 2>/dev/null || { skip "没装 doipclient"; exit 0; }

cleanup
echo "=== 起三台 ECU（含一台慢的）+ 网关 + 总线录制 ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 45 > /tmp/m10_c.log 2>&1 &
stdbuf -oL "$STUB" --iface "$IFACE" --fd --rx 18DA00F1 --tx 18DAF100 \
        --vin LSVCC0000C7654321 --hw HW03 --seconds 45 > /tmp/m10_fd.log 2>&1 &
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7B0 --tx 7B8 --delay-ms 700 \
        --vin LSVSS0000S7654321 --hw HW04 --seconds 45 > /tmp/m10_slow.log 2>&1 &
candump -L "$IFACE" > "$CANLOG" 2>&1 &
# 22 秒后自己退出并打印账（脚本最后用 sleep 等它退，不靠 signal）
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 22 \
    --route 0003:7A0:7A8:ECU_C \
    --route 0006:18DA00F1:18DAF100:ECU_FD:fd \
    --route 0007:7B0:7B8:ECU_SLOW > "$GWLOG" 2>&1 &

for i in $(seq 1 40); do
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&-; break; }
    sleep 0.2
done
sleep 1

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }
snap()   { wc -l < "$CANLOG"; }

read_vin() {   # $1=ta $2=sa
    "$PY" "$HERE/m5_check.py" read --host 127.0.0.1 --port "$PORT" \
          --ta "$1" --sa "$2" --uds "22 F1 90" 2>&1 | sed -n 's/^VIN=//p'
}

# ---- 1. 启动 ----
echo
echo "=== 1 启动：三条通道、三种速度 ==="
grep -q "TA=0x0003 →" "$GWLOG" && grep -q "TA=0x0006 →" "$GWLOG" && grep -q "TA=0x0007 →" "$GWLOG" \
    && ok "网关开了三条通道（0x0003 / 0x0006 / 0x0007）" || bad "网关通道数不对"
grep -q "先睡 700 ms" /tmp/m10_slow.log \
    && ok "慢 ECU 声明了自己每条应答前睡 700ms" || bad "慢 ECU 的启动行不对"

# ---- 2. 两条不同通道并行 ----
echo
echo "=== 2 两条不同通道：同时问，各拿各的 ==="
( read_vin 0x0006 0x0E11 > /tmp/m10_v_fd.txt ) &
p1=$!
( read_vin 0x0003 0x0E12 > /tmp/m10_v_c.txt ) &
p2=$!
wait $p1 $p2
[ "$(cat /tmp/m10_v_fd.txt)" = "LSVCC0000C7654321" ] \
    && ok "FD 通道拿到自己的 VIN（LSVCC…）" || bad "FD 通道 VIN 不对"
[ "$(cat /tmp/m10_v_c.txt)" = "LSVZZ0000B7654321" ] \
    && ok "经典通道拿到自己的 VIN（LSVZZ…），两条答案没串" || bad "经典通道 VIN 不对"

# ---- 3. 慢通道不拖累快通道 ----
echo
echo "=== 3 一台慢 ECU 只慢它自己那条通道 ==="
t0=$(now_ms)
( read_vin 0x0007 0x0E13 > /tmp/m10_v_slow.txt ) &
slow=$!
sleep 0.2
t1=$(now_ms)
fast_vin=$(read_vin 0x0003 0x0E14)
t2=$(now_ms)
fast_ms=$(( t2 - t1 ))
[ "$fast_vin" = "LSVZZ0000B7654321" ] && ok "慢请求还在飞的时候，快通道照常拿到了 VIN" \
    || bad "慢请求期间快通道没拿到 VIN"
[ "$fast_ms" -lt 300 ] && ok "快通道耗时 ${fast_ms}ms（< 300ms，没有等那条 700ms 的）" \
    || bad "快通道耗时 ${fast_ms}ms，被慢通道拖住了"
wait $slow
t3=$(now_ms)
slow_ms=$(( t3 - t0 ))
[ "$(cat /tmp/m10_v_slow.txt)" = "LSVSS0000S7654321" ] && ok "慢通道最终也拿到自己的 VIN（LSVSS…）" \
    || bad "慢通道 VIN 不对"
[ "$slow_ms" -ge 650 ] && ok "慢通道总耗时 ${slow_ms}ms（≥ 700ms 的量级，慢是真的慢）" \
    || bad "慢通道只用了 ${slow_ms}ms，慢 ECU 没生效？"

# ---- 4. 同一条通道：两个 tester 必须排队 ----
echo
echo "=== 4 同一条通道：两个 tester 抢同一台 ECU ==="
mark=$(snap)
( read_vin 0x0003 0x0E15 > /tmp/m10_q1.txt ) &
q1=$!
( read_vin 0x0003 0x0E16 > /tmp/m10_q2.txt ) &
q2=$!
wait $q1 $q2
[ "$(cat /tmp/m10_q1.txt)" = "LSVZZ0000B7654321" ] && ok "T1 拿到 VIN" || bad "T1 的 VIN 不对"
[ "$(cat /tmp/m10_q2.txt)" = "LSVZZ0000B7654321" ] && ok "T2 拿到 VIN（两条都成功，说明是排队不是丢弃）" || bad "T2 的 VIN 不对"
sleep 1
tail -n +$(( mark + 1 )) "$CANLOG" | grep "7A8#" > /tmp/m10_win.txt
$PY - <<"PY" > /tmp/m10_seq.txt
seq = []
for line in open("/tmp/m10_win.txt"):
    parts = line.split("#")
    if len(parts) < 2: continue
    seq.append(parts[1][:4])
# 首帧 10xx（0x10 多帧），后面应当紧跟 21xx 与 22xx，
# 也就是"这一条答完了再开始下一条"，中间不许插进别人的 FF。
# 注意 candump -L 的 data 是十六进制串：前两个字符就是 ISO-TP 的第一个字节
# （首帧的 PCI 是 0x10xx，`1014` = 10 + 长度 0x14），后面两帧的 PCI 是 21 / 22。
ff = [i for i, s in enumerate(seq) if s[:2] == "10"]
bad = []
for i in ff:
    if i + 2 >= len(seq):
        bad.append(i); continue
    if seq[i+1][:2] != "21" or seq[i+2][:2] != "22":
        bad.append(i)
print("SEQ=" + " ".join(seq))
print("OK" if (len(ff) == 2 and not bad) else "NO")
PY
head -1 /tmp/m10_seq.txt | sed 's/^/      /'
grep -q "^OK$" /tmp/m10_seq.txt \
    && ok "总线上的两组帧是 FF+CF1+CF2、FF+CF1+CF2，没有交叉（同通道真串行）" \
    || bad "总线上的两组帧交叉了（同通道串行被破坏）"

# ---- 5. 同一条连接连发两条：第二条当场拒 ----
echo
echo "=== 5 同一条连接连发两条：第二条当场拒（没有流水线语义）==="
OUT=$("$PY" "$HERE/m5_check.py" busy --host 127.0.0.1 --port "$PORT" \
        --ta 0x0003 --sa 0x0E17 --uds "22 F1 90" 2>&1)
echo "$OUT" | grep -q "SEEN=.*ACK" && ok "第一条被受理（0x8002 ACK）" || bad "第一条没被受理"
echo "$OUT" | grep -q "NACK_CODE=0x08" && ok "第二条当场拒：0x8003 0x08" || bad "第二条没有被拒（$(echo "$OUT" | grep NACK_CODE)）"

# ---- 6. 连接断了，在途请求作废 ----
echo
echo "=== 6 断开时在途请求作废：结果不转给下一个诊断仪 ==="
$PY - <<PY
import socket, struct
s = socket.create_connection(("127.0.0.1", $PORT), timeout=2)
def msg(t, p): s.sendall(bytes([0x02, 0xFD]) + struct.pack("!HL", t, len(p)) + p)
msg(0x0005, struct.pack("!HBL", 0x0E18, 0x00, 0) + b"\x00\x00\x00\x00")
s.recv(64)
msg(0x8001, struct.pack("!HH", 0x0E18, 0x0007) + b"\x22\xF1\x90")   # 慢通道，700ms 后才回
s.close()
print("SENT_THEN_CLOSED")
PY
sleep 1
got=$(read_vin 0x0003 0x0E19)
[ "$got" = "LSVZZ0000B7654321" ] && ok "后来的诊断仪拿到的是自己的 VIN，不是那条孤儿结果" \
    || bad "后来的诊断仪拿到的 VIN 不对（$got）"

# ---- 7. 压力：3 个 tester × 5 条，交替两个通道 ----
echo
echo "=== 7 压力：3 个 tester 各 5 条，交替打两个通道 ==="
tester() {   # $1=sa 起点
    local sa=$1 i
    for i in $(seq 0 4); do
        if [ $(( i % 2 )) -eq 0 ]; then
            read_vin 0x0003 $(( sa + i ))
        else
            read_vin 0x0006 $(( sa + i ))
        fi
    done
}
( tester 0x0E20 > /tmp/m10_p1.txt ) &
pp1=$!
( tester 0x0E28 > /tmp/m10_p2.txt ) &
pp2=$!
( tester 0x0E30 > /tmp/m10_p3.txt ) &
pp3=$!
wait $pp1 $pp2 $pp3
n=$(cat /tmp/m10_p1.txt /tmp/m10_p2.txt /tmp/m10_p3.txt | grep -c '^LSV')
[ "$n" -eq 15 ] && ok "15 条请求全部拿到 VIN（不是 14 条也不是 16 条）" || bad "只拿到 $n 条 VIN"
# 三条顺序写错一个就是串包：前 5 条里 3 条经典 2 条 FD
mix=$(cat /tmp/m10_p1.txt | sed -n 's/^LSV\(..\).*/\1/p' | tr '\n' ' ')
[ "$mix" = "ZZ CC ZZ CC ZZ " ] && ok "同一个 tester 的 5 条交替正确（ZZ/CC 不串）" || bad "交替序列不对：$mix"

# ---- 8. 等网关自己退，看账 ----
echo
echo "=== 8 网关的账 ==="
for i in $(seq 1 40); do
    pgrep -x doip-gateway >/dev/null 2>&1 || break
    sleep 1
done
sleep 1
# 预期 24：S2 2 + S3 2 + S4 2 + S5 1（第二条被忙拒，根本没进网关）+ S6 2 + S7 15
grep -qE "^转发 24 条，失败 0 条" "$GWLOG" \
    && ok "转发 24 条、失败 0 条（2+2+2+1+2+15，忙拒那条没算进去）" \
    || bad "转发/失败对不上：$(grep -oE '转发 [0-9]+ 条，失败 [0-9]+ 条' "$GWLOG" | tail -1)"
grep -q "忙拒 1 条" "$GWLOG" && ok "忙拒记了 1 条（同一连接的第二条请求）" \
    || bad "忙拒计数不对：$(grep 忙拒 "$GWLOG")"
grep -q "作废 1 条" "$GWLOG" \
    && ok "断开时那条在途请求被作废（1 条）" || bad "作废数不是 1：$(grep 作废 "$GWLOG")"
grep -E "TA=0x0003.*排队峰值" "$GWLOG" | tail -1 > /tmp/m10_cs.txt
if grep -qE "排队峰值 [1-9]" /tmp/m10_cs.txt; then
    ok "经典通道确实排过队：$(sed 's/.*排队峰值/排队峰值/' /tmp/m10_cs.txt)"
else
    bad "经典通道没有排队记录（两个 tester 可能没真正同时到）"
fi

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M10 全绿 —— 一条通道一条队：慢的只慢自己，抢同一台 ECU 的排队而不是交叉。"
fi
exit $(( fail == 0 ? 0 : 1 ))
