#!/usr/bin/env bash
# =============================================================================
# m12_e2e.sh —— M12 验收：流式交付（收一条转一条，且一条都不发两遍）
#
# 用法： bash tools/m12_e2e.sh [流式端口] [攒批对照端口]      默认 13469 / 13470
#
# M11 量出来的病：网关把一轮广播的答案**攒齐**才一次性交回，
# 所以诊断仪看到第一条的时刻 = 最慢那台 ECU 答完的时刻（≈120~140ms）。
# 功能寻址问的是"这一类 ECU 谁在"，明明快的两台几十毫秒就答了，却要陪慢的等。
#
# 这一节的考点有两半，缺一不可：
#   ① **快的先到**：首条答案不再由"最慢那台"决定；
#   ② **同一条不发两遍**：边到边发 + 最后交卷，两条路径都在动同一批答案（StreamLedger 记账）。
#
# 拓扑（同一条 vcan0，三台 ECU 都听 7DF，两台网关同一张路由表）：
#   PORT  13469  流式（默认）        —— 每收一条立刻 0x8001 转给诊断仪
#   PORT2 13470  --no-stream 对照    —— M11 的老行为：攒齐再发
#   ECU_A 0x0003 经典 7A0/7A8   HW02  快
#   ECU_B 0x0006 FD  18DA00F1  HW03  快
#   ECU_C 0x0007 经典 7B0/7B8   HW04  **每条应答前睡 120ms**（慢的那台）
#
# 时间断言为什么这么写：stub 自己也有几十毫秒的采样抖动，所以别把"快"写成一个死数字，
# 而是 ① 同一次会话里的两端对比（流式首条 vs 攒批首条，差 ≥40ms）、② 用 SPAN（首末跨度）看形状。
# =============================================================================
set -u

PORT=${1:-13469}
PORT2=${2:-13470}
IFACE=${IFACE:-vcan0}
GW=$(cd "$(dirname "$0")/.." && pwd)/build/doip-gateway
STUB=$(cd "$(dirname "$0")/.." && pwd)/build/stub-ecu
CLIENT=$(cd "$(dirname "$0")/.." && pwd)/build/doip-client
CANLOG=/tmp/m12_can.log
SLOG=/tmp/m12_stream_gw.log      # 流式网关
NLOG=/tmp/m12_batch_gw.log       # 攒批对照网关
OUT=/tmp/m12_client.txt

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
echo "=== 起三台 ECU（快的两台 + 慢 120ms 的一台）+ 流式网关 + 攒批对照网关 ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 --func-rx 7DF \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 60 > /tmp/m12_a.log 2>&1 &
stdbuf -oL "$STUB" --iface "$IFACE" --fd --rx 18DA00F1 --tx 18DAF100 --func-rx 7DF \
        --vin LSVCC0000C7654321 --hw HW03 --seconds 60 > /tmp/m12_b.log 2>&1 &
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7B0 --tx 7B8 --func-rx 7DF \
        --vin LSVSS0000S7654321 --hw HW04 --delay-ms 120 --seconds 60 > /tmp/m12_c.log 2>&1 &
candump -L "$IFACE" > "$CANLOG" 2>&1 &

ROUTES="--route 0003:7A0:7A8:ECU_A --route 0006:18DA00F1:18DAF100:ECU_B:fd --route 0007:7B0:7B8:ECU_C --func 0xE400:0x7DF:ALL"
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT"  --seconds 46 $ROUTES > "$SLOG" 2>&1 &
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT2" --seconds 42 --no-stream $ROUTES > "$NLOG" 2>&1 &

for p in "$PORT" "$PORT2"; do
    for i in $(seq 1 40); do
        (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && { exec 3>&-; break; }
        sleep 0.2
    done
done
sleep 1

DID="22 F1 91"
grab() { sed -n "s/^$1=//p" "$OUT" | tr -d '\r' | tail -1; }
runS() { "$CLIENT" --port "$PORT"  --sa "$1" --ta 0xE400 --diag "$DID" --all "${@:2}" > "$OUT" 2>&1; }
runN() { "$CLIENT" --port "$PORT2" --sa "$1" --ta 0xE400 --diag "$DID" --all "${@:2}" > "$OUT" 2>&1; }

# ---- 1. 启动：两种交付方式各就各位 ----
echo
echo "=== 1 启动：流式网关 / 攒批对照网关 / 三台 ECU ==="
grep -q "交付方式：流式" "$SLOG" && ok "流式网关：交付方式 = 流式（收一条转一条）" || bad "流式网关没打出流式模式"
grep -q "交付方式：攒批" "$NLOG" && ok "对照网关：--no-stream 生效（回到 M11 的攒批）" || bad "--no-stream 没生效"
grep -q "TA=0x0007 → 0x7B0" "$SLOG" && ok "流式网关三条物理通道都开了" || bad "流式网关通道没开全"

# 先打一轮热身，把"第一次广播"的冷启动抖动吃掉（不计入断言）
runS 0x0E10 --window 900 >/dev/null
sleep 0.4

# ---- 2. 流式：首条答案不再等最慢那台 ----
echo
echo "=== 2 流式：三条答案，快的先到（FIRST_AT 小、SPAN 大）==="
runS 0x0E11 --window 300 --trace
sCnt=$(grab RESPONSE_COUNT)
sFirst=$(grab FIRST_AT)
sLast=$(grab LAST_AT)
sSpan=$(grab SPAN_AT)
[ "$sCnt" = "3" ] && ok "流式：RESPONSE_COUNT=3（三条一条不少）" || bad "流式 RESPONSE_COUNT=$sCnt（期望 3）"
echo "      FIRST_AT=${sFirst}ms  LAST_AT=${sLast}ms  SPAN_AT=${sSpan}ms"
[ -n "$sFirst" ] && [ "$sFirst" -ge 0 ] && [ "$sFirst" -le 50 ] \
    && ok "首条 ${sFirst}ms 到手（≤50）" || bad "首条 ${sFirst}ms（期望 ≤50）"
[ -n "$sLast" ] && [ "$sLast" -ge 100 ] \
    && ok "最后一条 ${sLast}ms 才到（≥100：慢的那台确实慢约 120ms）" || bad "末条 ${sLast}ms（期望 ≥100）"
[ -n "$sSpan" ] && [ "$sSpan" -ge 90 ] \
    && ok "首末跨度 ${sSpan}ms（≥90：答案是陆续到的，不是一整批）" || bad "跨度 ${sSpan}ms（期望 ≥90）"

# ---- 3. 攒批对照：同一台车、同一条总线，首条被拖住 ----
echo
echo "=== 3 攒批对照（--no-stream）：首条要等最慢那台 ==="
sleep 0.4
runN 0x0E12 --window 300 --trace
nCnt=$(grab RESPONSE_COUNT)
nFirst=$(grab FIRST_AT)
nSpan=$(grab SPAN_AT)
[ "$nCnt" = "3" ] && ok "对照：RESPONSE_COUNT=3" || bad "对照 RESPONSE_COUNT=$nCnt（期望 3）"
echo "      FIRST_AT=${nFirst}ms  SPAN_AT=${nSpan}ms"
[ -n "$nSpan" ] && [ "$nSpan" -le 20 ] \
    && ok "对照：首末跨度 ${nSpan}ms（≤20：三条是一口气到齐的）" || bad "对照跨度 ${nSpan}ms（期望 ≤20）"
[ -n "$nFirst" ] && [ "$nFirst" -ge 100 ] \
    && ok "对照：首条 ${nFirst}ms 才到（≥100：整批由最慢那台决定）" || bad "对照首条 ${nFirst}ms（期望 ≥100）"
if [ -n "$sFirst" ] && [ -n "$nFirst" ] && [ $((nFirst - sFirst)) -ge 80 ]; then
    ok "同一个场景下，流式首条比攒批首条早 $((nFirst - sFirst))ms（≥80ms 就是 M12 的收益）"
else
    bad "两种交付的首条差只有 $(( ${nFirst:-0} - ${sFirst:-0} ))ms（期望 ≥80）"
fi

# ---- 4. 边到边发 + 最后交卷，同一条不许发两遍 ----
echo
echo "=== 4 不重发：计数与归档都不许多出来 ==="
sleep 0.4
runS 0x0E13 --window 900
cnt=$(grab RESPONSE_COUNT)
arr=$(grab RESPONSE_ARRIVALS)
dup=$(grab COLLECTOR_DUPLICATES)
sas=$(grab RESPONSE_SAS)
[ "$cnt" = "3" ] && [ "$arr" = "3" ] \
    && ok "流式一轮：3 台 / 到过 3 条（若重发会变成到过 4~6 条）" || bad "count=$cnt arrivals=$arr"
[ "$dup" = "0" ] && ok "COLLECTOR_DUPLICATES=0（同一台没有被发两遍）" || bad "出现重复 $dup 条"
[ "$sas" = "0x0003,0x0006,0x0007" ] && ok "三台 SA 各一条，没有谁被补发成两条" || bad "RESPONSE_SAS=$sas"
grep -q "流式已发 3 条）→ 补齐 0 条" "$SLOG" \
    && ok "网关账：3 条全流式发出，交卷补齐 0 条（账把重复发挡住了）" \
    || bad "没看到「流式已发 3 条 → 补齐 0 条」：$(grep -o "流式已发 .* 条）→ 补齐 .* 条" "$SLOG" | tail -1)"

# ---- 5. 窗口比慢的那台短：流式下是"收到 2 条"，不是"整批 0 条" ----
#
# 实测（关掉 Nagle 之后）：快两台 ≈0ms 到、慢的 ≈122ms 到。窗口取 40ms：
# 比"快慢间隔"（≈120ms）小得多（第三条进不来），也比攒批那个"整批时刻"小。
echo
echo "=== 5 窗口 40ms：流式下拿到快的两条，慢的还没到 ==="
sleep 0.4
runS 0x0E14 --window 40 --trace; cp "$OUT" /tmp/m12_step5.txt
cnt=$(grab RESPONSE_COUNT)
[ "$cnt" = "2" ] && ok "窗口 40ms 收到 $cnt 条（M12 前这是整批 0 条）" || bad "窗口 40ms 收到 $cnt 条（期望 2）"

# ---- 6. 提前断线：迟到的流式答案不许转给别人 ----
echo
echo "=== 6 提前断线：慢的那条到的时候人已经走了 ==="
sleep 0.4
runS 0x0E15 --window 20      # 快的两条到手后就挂断，慢的还在路上
sleep 1.5                    # 等慢的那条到达 + 网关把它判成"连接已断"
grep -q "流式送达时连接已断" "$SLOG" \
    && ok "网关记账：流式送达时连接已断 ≥1 条（丢弃不转交）" || bad "没记到断线丢弃"
runS 0x0E16 --window 900      # 下一位诊断仪：只拿自己的答案
cnt=$(grab RESPONSE_COUNT)
[ "$cnt" = "3" ] && ok "下一位 tester 拿到自己的 3 条（前一位的残留没有混进来）" || bad "下一位收到 $cnt 条"

# ---- 7. 账 + 总线取证 ----
echo
echo "=== 7 等两个网关退场，核账与总线 ==="
for i in $(seq 1 60); do
    pgrep -x doip-gateway >/dev/null 2>&1 || break
    sleep 1
done
sleep 1

sb=$(grep -oE "广播 [0-9]+ 次" "$SLOG" | tail -1 | grep -oE "[0-9]+")
sr=$(grep -oE "收回应答 [0-9]+ 条" "$SLOG" | tail -1 | grep -oE "[0-9]+")
[ "${sb:-0}" = "6" ] && ok "流式网关：广播 6 次（热身 1 + 第 2/4/5/6 步 5 次）" || bad "流式网关广播 ${sb:-?} 次（期望 6）"
[ "${sr:-0}" = "18" ] && ok "流式网关：收回应答 18 条（每次 3 台都答，客户端提前走的也算）" || bad "流式网关收回应答 ${sr:-?} 条"
sd=$(grep -oE "流式交付 [0-9]+ 条" "$SLOG" | tail -1 | grep -oE "[0-9]+")
[ "${sd:-0}" -ge 12 ] && ok "流式网关：真正流式送达 ${sd} 条（≥12）" || bad "流式交付只有 ${sd:-?} 条（期望 ≥12）"
drop=$(grep -oE "流式时连接已断 [0-9]+ 条" "$SLOG" | tail -1 | grep -oE "[0-9]+")
[ "${drop:-0}" -ge 1 ] && ok "流式网关：断线丢弃 ${drop} 条（≥1）" || bad "断线丢弃 ${drop:-?} 条"
nb=$(grep -oE "广播 [0-9]+ 次" "$NLOG" | tail -1 | grep -oE "[0-9]+")
[ "${nb:-0}" = "1" ] && ok "对照网关：广播 1 次" || bad "对照网关广播 ${nb:-?} 次（期望 1）"
if grep -q "流式交付" "$NLOG"; then bad "对照网关不该有流式账"; else ok "对照网关没有流式账（--no-stream 是真关掉了）"; fi

n=$(grep -c "7DF#" "$CANLOG")
want=$(( ${sb:-0} + ${nb:-0} ))
[ "$n" -eq "$want" ] && ok "总线：7DF 广播帧 $n 条 = 两台网关广播次数之和（一次广播一帧）" \
    || bad "总线上 7DF 帧 $n 条（期望 $want）"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M12 全绿 —— 收一条转一条：首条不再被最慢那台拖住，而同一条答案一条也没多发。"
fi
exit $(( fail == 0 ? 0 : 1 ))
