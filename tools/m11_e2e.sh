#!/usr/bin/env bash
# =============================================================================
# m11_e2e.sh —— M11 验收：诊断仪侧多响应配对（一条广播，几台 ECU 各答一句）
#
# 用法： bash tools/m11_e2e.sh [端口] [第二端口]     默认 13467 / 13468
#
# 这一步的考点全在"收"上，不在"发"上。M8 已经证明网关能把几条答案逐条送回，
# 但诊断仪那边只会读第一条——功能寻址的整个意义就废了。
#
# 要证明的四件事：
#   ① 答案条数不由网关决定，由"谁在听"决定；
#   ② 每条答案归谁，只能按 SA 认，不能按"第几条"猜；
#   ③ "收齐了吗"协议层没有答案——只能靠静默窗口，窗口太短就会漏；
#   ④ 没有答案的两种情形要分得清：没人听（0x06）与地址不认识（0x03）。
#
# 拓扑（同一条 vcan0，三台 ECU 都听 7DF）：
#   ECU_A（经典 7A0/7A8）     TA=0x0003，HW02（22 F1 91 只有 6 字节，能进单帧）
#   ECU_B（FD 18DA00F1/…）    TA=0x0006，HW03
#   ECU_C（经典 7B0/7B8）     TA=0x0007，HW04，**每条应答前睡 120ms**（网关窗口 150ms 收得到，客户端窗口 80ms 就收不到）
# 第二个网关（另一个端口）只挂一个"没人听"的功能地址 5DF，用来验 0x06。
# =============================================================================
set -u

PORT=${1:-13467}
PORT2=${2:-13468}
IFACE=${IFACE:-vcan0}
GW=$(cd "$(dirname "$0")/.." && pwd)/build/doip-gateway
STUB=$(cd "$(dirname "$0")/.." && pwd)/build/stub-ecu
CLIENT=$(cd "$(dirname "$0")/.." && pwd)/build/doip-client
PY=${PY:-python3}
CANLOG=/tmp/m11_can.log
GWLOG=/tmp/m11_gw.log
GW2LOG=/tmp/m11_gw2.log
OUT=/tmp/m11_client.txt

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
[ -x "$STUB" ]   || { skip "没有 $STUB（先 cmake --build build）"; exit 0; }
[ -x "$GW" ]     || { skip "没有 $GW"; exit 0; }
[ -x "$CLIENT" ] || { skip "没有 $CLIENT"; exit 0; }
command -v candump >/dev/null 2>&1 || { skip "没有 candump"; exit 0; }

cleanup
echo "=== 起三台都听 7DF 的 ECU + 两个网关（一个有人听、一个没人听）+ 总线录制 ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 --func-rx 7DF \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 42 > /tmp/m11_a.log 2>&1 &
stdbuf -oL "$STUB" --iface "$IFACE" --fd --rx 18DA00F1 --tx 18DAF100 --func-rx 7DF \
        --vin LSVCC0000C7654321 --hw HW03 --seconds 42 > /tmp/m11_b.log 2>&1 &
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7B0 --tx 7B8 --func-rx 7DF \
        --vin LSVSS0000S7654321 --hw HW04 --delay-ms 120 --seconds 42 > /tmp/m11_c.log 2>&1 &
candump -L "$IFACE" > "$CANLOG" 2>&1 &

stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 26 \
    --route 0003:7A0:7A8:ECU_A \
    --route 0006:18DA00F1:18DAF100:ECU_B:fd \
    --route 0007:7B0:7B8:ECU_C \
    --func 0xE400:0x7DF:ALL > "$GWLOG" 2>&1 &

stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT2" --seconds 16 \
    --route 0009:7C0:7C8:ECU_DEAF \
    --func 0xE400:0x5DF:NOBODY > "$GW2LOG" 2>&1 &

for i in $(seq 1 40); do
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&-; break; }
    sleep 0.2
done
sleep 1

# 读的 DID 必须是"能塞进单帧的小响应"：功能寻址的请求是单帧，ECU 也只能单帧答，
# 所以 VIN（20 字节）在广播上根本没有答案（M8 的边界之二）。这里读硬件号 F191（6 字节）。
DID="22 F1 91"
run() { "$CLIENT" --port "$PORT" --sa "$1" --ta "$2" --diag "$DID" "${@:3}" > "$OUT" 2>&1; }
grab() { sed -n "s/^$1=//p" "$OUT" | tr -d '\r'; }

# ---- 1. 启动：两张功能路由，一张有人听、一张没人听 ----
echo
echo "=== 1 启动：3 条物理通道 + 功能路由 7DF / 5DF ==="
grep -q "TA=0x0003 → 0x7A0" "$GWLOG" && grep -q "TA=0x0006 → 0x18DA00F1" "$GWLOG" \
    && grep -q "TA=0x0007 → 0x7B0" "$GWLOG" \
    && ok "主网关三条通道都开了" || bad "主网关通道没开全"
grep -q "TA=0xE400 → 0x7DF" "$GWLOG" && ok "功能路由 0xE400 → 0x7DF（三台 ECU 都在听）" \
    || bad "主网关功能路由不对"
grep -q "TA=0xE400 → 0x5DF" "$GW2LOG" && ok "第二个网关的功能路由 0xE400 → 0x5DF（没人听）" \
    || bad "第二个网关功能路由不对"

# ---- 2. 物理寻址：还是只收一条（M11 没把老路径改坏） ----
echo
echo "=== 2 物理寻址回归：一条请求一条答案 ==="
run 0x0E01 0x0003
grep -q "← 0x8001 响应：SA=0x0003" "$OUT" && grep -q "62 F1 91" "$OUT" && ok "物理寻址：拿到 SA=0x0003 的那一条（HW02）" || bad "物理寻址没拿到答案"
if grep -q "RESPONSE_COUNT" "$OUT"; then
    bad "没带 --all 却打了汇总（不该发生）"
else
    ok "没带 --all 时不打汇总（老用法原样）"
fi

# ---- 3. 功能寻址：收齐三条 ----
echo
echo "=== 3 功能寻址 --all：三条答案，一个不丢 ==="
run 0x0E02 0xE400 --all --window 900
cnt=$(grab RESPONSE_COUNT)
[ "$cnt" = "3" ] && ok "RESPONSE_COUNT=3（谁在听，谁答）" || bad "RESPONSE_COUNT=$cnt（期望 3）"
sas=$(grab RESPONSE_SAS)
[ "$sas" = "0x0003,0x0006,0x0007" ] \
    && ok "RESPONSE_SAS=$sas（按到达顺序 = 网关按 TA 升序轮询通道）" || bad "RESPONSE_SAS=$sas"
dup=$(grab COLLECTOR_DUPLICATES)
chg=$(grab COLLECTOR_CHANGES)
[ "$dup" = "0" ] && [ "$chg" = "0" ] && ok "没有重复、没有改口（每台只答一次）" \
    || bad "重复 $dup / 改口 $chg"
grep -q "静默 900ms 无新响应，收工" "$OUT" && ok "收工靠静默满窗口（不是「收够了」）" \
    || bad "没有静默收工的日志"

# ---- 4. 每条答案归谁：VIN 必须和自己的 SA 对上 ----
echo
echo "=== 4 归档：每条答案的硬件号必须和自己的 SA 对上 ==="
$PY - <<"PY" > /tmp/m11_pairs.txt
want = {"0003": "HW02", "0006": "HW03", "0007": "HW04"}
txt = open("/tmp/m11_client.txt").read()
pairs, order = {}, []
for line in txt.splitlines():
    if line.startswith("RESP") and "_SA=" in line:
        order.append(line.split("=", 1)[1].strip().replace("0x", ""))
    elif line.startswith("RESP") and "_HEX=" in line:
        pairs[order[-1]] = bytes(int(h, 16) for h in line.split("=", 1)[1].split())[3:].decode("ascii", "replace")
print("PAIRS=" + " ".join(k + ":" + v for k, v in pairs.items()))
print("OK" if (len(pairs) == 3 and all(want.get(k) == v for k, v in pairs.items())) else "NO")
PY
sed -n "s/^PAIRS=/      PAIRS=/p" /tmp/m11_pairs.txt
grep -q "^OK$" /tmp/m11_pairs.txt && ok "三台 ECU 的硬件号各自对得上（HW02 / HW03 / HW04 没串）" \
    || bad "有硬件号和 SA 对不上（答案被错配了）"

# ---- 5. 窗口比网关的节拍还短：一条都收不到 ----
#
# 三台 ECU 里，ECU_C 每条应答前睡 120ms。网关是"一轮广播攒齐所有答案再一次交回"，
# 所以整批答案到诊断仪的时刻由**最慢的那台**决定（≈130ms）。
# 客户端窗口若小于这个时刻，就不是"少收一条"，而是**整批一条都收不到**——
# 但网关账上那三条是实实在在收到了的（第 9 步的 15 条就是证据）。
echo
echo "=== 5 窗口比最慢的那台还短：80 → 0 条，300 → 3 条 ==="
run 0x0E03 0xE400 --all --window 80
cnt=$(grab RESPONSE_COUNT)
[ "$cnt" = "0" ] && ok "窗口 80ms：整批都没等到（最慢的一台 120ms，网关攒齐才发）" \
    || bad "窗口 80ms 收到 $cnt 条（期望 0）"
grep -q "一条都没有" "$OUT" && ok "客户端如实报「一条都没有」——而网关其实收齐了三条" \
    || bad "零响应的提示缺失"
run 0x0E08 0xE400 --all --window 300
cnt=$(grab RESPONSE_COUNT)
[ "$cnt" = "3" ] && ok "窗口 300ms 把慢的也等到了：三条全收" || bad "窗口 300ms 收到 $cnt 条"

# ---- 6. 连着两轮：上一轮的答案不许混进来 ----
echo
echo "=== 6 连跑两轮：第二轮只算第二轮的 ==="
run 0x0E04 0xE400 --all --window 900
run 0x0E05 0xE400 --all --window 900
cnt=$(grab RESPONSE_COUNT)
arr=$(grab RESPONSE_ARRIVALS)
[ "$cnt" = "3" ] && [ "$arr" = "3" ] && ok "第二轮仍是 3 台 / 3 条（没把上一轮的残留算进来）" \
    || bad "第二轮 count=$cnt arrivals=$arr"

# ---- 7. 没人听：0x06 ----
echo
echo "=== 7 功能地址没人听：0x8003 0x06，零条答案 ==="
"$CLIENT" --port "$PORT2" --sa 0x0E06 --ta 0xE400 --diag "22 F1 91" --all > /tmp/m11_no.txt 2>&1
grep -q "0x8003 NACK" /tmp/m11_no.txt && grep -q "code=0x06" /tmp/m11_no.txt \
    && ok "没人听 → NACK 0x06（广播出去了，没有一台应答）" || bad "0x06 没出现"
grep -q "RESPONSE_COUNT=0" /tmp/m11_no.txt && ok "RESPONSE_COUNT=0（连门都没进，更没有答案）" \
    || bad "零响应的输出不对"

# ---- 8. 地址不认识：0x03 ----
echo
echo "=== 8 物理地址不在表里：0x8003 0x03 ==="
run 0x0E07 0x0009 --all
grep -q "code=0x03" "$OUT" && ok "地址不认识 → NACK 0x03" || bad "0x03 没出现"
grep -q "RESPONSE_COUNT=0" "$OUT" \
    && ok "同样 0 条，但码不同：0x03 是「问错人」，0x06 是「没人理」" || bad "零响应的输出不对"

# ---- 9. 账 + 总线取证 ----
echo
echo "=== 9 网关的账与总线上的广播 ==="
for i in $(seq 1 40); do
    pgrep -x doip-gateway >/dev/null 2>&1 || break
    sleep 1
done
sleep 1
# 广播次数：step3 1 + step5 2 + step6 2 = 5；每次三台都答（ECU_C 只是慢 120ms，仍在内）→ 15 条
grep -q "功能寻址：广播 5 次，收回应答 15 条，无人应答 0 次" "$GWLOG" \
    && ok "账：广播 5 次、收回应答 15 条（5 × 3 台，客户端没收到也算在网关账上）" \
    || bad "功能寻址的账不对：$(grep 功能寻址 "$GWLOG" | tail -1)"
n=$(grep -c "7DF#" "$CANLOG")
[ "$n" -eq 5 ] && ok "总线上 7DF 广播帧正好 5 条（一次广播 = 一帧请求）" \
    || bad "总线上 7DF 帧有 $n 条（期望 5）"
echo "      $(grep -oE "在途丢弃 [0-9]+ 条" "$GWLOG" | tail -1) / $(grep -oE "作废 [0-9]+ 条" "$GWLOG" | tail -1)"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M11 全绿 —— 一条广播三台答：按 SA 归档，靠静默窗口收工；窗口短了可能整批收不到，但绝不串味。"
fi
exit $(( fail == 0 ? 0 : 1 ))
