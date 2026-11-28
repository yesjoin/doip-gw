#!/usr/bin/env bash
# ============================================================================
# m34_e2e.sh —— M34 端到端：多份越权账合并
#
# 段一  跑三次网关，落三份账（每次只在一份账里出现）：
#       run1 读档 0x0E00 撞 5 次 → 账1 一条 ×5
#       run2 读档 0x0E00 撞 3 次 → 账2 一条 ×3（与账1 同一组）
#       run3 写档 0x0E01 撞 2 次 → 账3 一条 ×2（换人，另一组）
# 段二  合并三份：合计 10 次 / 2 组；每份分布 5/3/0 与 0/0/2
#       并且报「只并计数、不并秒」（这是 M34 的核心口径）
# 段三  边界：单份合并 = 单份读、一份坏就整次不给、两个开关互斥、没给文件算用法错
#
# 用法：bash tools/m34_e2e.sh [port] [port2]
# ============================================================================
set -u
PORT="${1:-13512}"
PORT2="${2:-13513}"
GW=./build/doip-gateway
ECU=./build/stub-ecu
DN=./build/doip-deny
PY=python3
STD="stdbuf -oL -eL"
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
FAIL=0
PASS=0

ck() {
    local want="$1" got="$2" what="$3"
    if [ "$want" = "$got" ]; then
        PASS=$((PASS + 1))
        printf '[ok ] %s\n' "$what"
    else
        FAIL=$((FAIL + 1))
        printf '[FAIL] %s（期望 %s，实到 %s）\n' "$what" "$want" "$got"
    fi
}

clean_state() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    sleep 0.4
}

# 跑一次：起 ECU + 网关（开防火墙 + DID 白名单 + 越权账），让指定 SA 撞 times 次。
run_once() {
    local port="$1" sa="$2" times="$3" ledger="$4"
    clean_state
    $STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
        --battery-mv 12100 --delay-ms 8 --seconds 14 \
        --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu.$port.log" 2>&1 &
    sleep 1.2
    $STD "$GW" --iface vcan0 --port "$port" --seconds 9 \
        --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
        --enforce-ops --grant 0E00:read --grant 0E01:write --default-grant read \
        --did-guard --did-default guarded --did F1B0:secret \
        --deny-ledger "$ledger" > "$TMP/gw.$port.log" 2>&1 &
    local gwpid=$!
    sleep 1.0
    $PY "$HERE/m34_check.py" "$port" "$sa" "$times" > "$TMP/hit.$sa.$port.log" 2>&1
    local rc=$?
    wait "$gwpid" 2>/dev/null
    sleep 0.2
    return $rc
}

echo "=== 环境 ==="
[ -d /sys/class/net/vcan0 ] || { echo "[FAIL] vcan0 不存在"; exit 1; }
die() { echo "[FAIL] $1"; clean_state; exit 1; }
[ -x "$GW" ] || die "没有 $GW"
[ -x "$ECU" ] || die "没有 $ECU"
[ -x "$DN" ] || die "没有 $DN"

# ============================================================================
echo "=== 段一：三次运行，三份账（5 次 / 3 次 / 2 次） ==="
# ============================================================================
run_once "$PORT" 0E00 5 "$TMP/d1.txt"
ck "0" "$?" "run1：读档撞 5 次全中"
ck "5" "$(sed -n 's/^HIT_33=//p' "$TMP/hit.0E00.$PORT.log")" "run1 撞中 5 次"
ck "1" "$(grep -c '^D ' "$TMP/d1.txt")" "账1 只有一组"
ck "1" "$(grep -cF '00000005' "$TMP/d1.txt")" "账1 记的是 5 次"

run_once "$PORT" 0E00 3 "$TMP/d2.txt"
ck "0" "$?" "run2：读档撞 3 次全中"
ck "1" "$(grep -cF '00000003' "$TMP/d2.txt")" "账2 记的是 3 次（同一组，跨运行分成两份账）"

run_once "$PORT2" 0E01 2 "$TMP/d3.txt"
ck "0" "$?" "run3：写档撞 2 次全中"
ck "1" "$(grep -cF 'D 0E01 22 F1B0' "$TMP/d3.txt")" "账3 记的是另一台 SA（0x0E01）"
ck "1" "$(grep -cF '00000002' "$TMP/d3.txt")" "账3 记的是 2 次"

# 三份账各自自洽：单份读只看得见自己那点
"$DN" --ledger "$TMP/d1.txt" > "$TMP/one.log" 2>&1
ck "1" "$(grep -cF '合计：5 次挡回，1 条记录' "$TMP/one.log")" "单份读：账1 只有 5 次（看不见另外两份）"
ck "1" "$(grep -cF '本次运行第' "$TMP/one.log")" "单份读有本次运行的时间窗（合并后就没有了）"

# ============================================================================
echo "=== 段二：合并三份 —— 只并计数、不并秒 ==="
# ============================================================================
"$DN" --merge "$TMP/d1.txt" "$TMP/d2.txt" "$TMP/d3.txt" > "$TMP/merge.log" 2>&1
MERGE=$?
cat "$TMP/merge.log"

ck "0" "$MERGE" "合并读通（退出码 0）"
ck "1" "$(grep -cF '越权账合并：3 份' "$TMP/merge.log")" "点名合并了几份"
ck "1" "$(grep -cF '合计：10 次挡回，2 组记录' "$TMP/merge.log")" "合计：5+3+2=10 次，2 组"
ck "1" "$(grep -cF '合并账不套单账' "$TMP/merge.log")" "说明合并账不受单账 32 组上限约束"
ck "1" "$(grep -cF '只并计数、不并秒' "$TMP/merge.log")" "核心口径写在输出里"
ck "0" "$(grep -cF '本次运行第' "$TMP/merge.log")" "合并输出里没有时间窗（秒不可跨运行比）"
ck "1" "$(grep -cF '  0x0E00：8 次（出现于 2/3 份）' "$TMP/merge.log")" "按 SA：0x0E00 8 次、2 份里出现"
ck "1" "$(grep -cF '  0x0E01：2 次（出现于 1/3 份）' "$TMP/merge.log")" "按 SA：0x0E01 只来过 1 份"
ck "1" "$(grep -cF 'DID 0xF1B0（钥匙表）：10 次（出现于 3/3 份）' "$TMP/merge.log")" \
    "按对象：钥匙表被试探 10 次、3 份里都出现"
ck "1" "$(grep -cF '×8  （每份：5/3/0）' "$TMP/merge.log")" "明细：总量 8，分布 5/3/0（第 3 份没有）"
ck "1" "$(grep -cF '×2  （每份：0/0/2）' "$TMP/merge.log")" "明细：总量 2，分布 0/0/2（只第 3 份有）"

# 顺序无关：换一下文件顺序，结果应当完全一样（只并计数，不依赖先后）
"$DN" --merge "$TMP/d3.txt" "$TMP/d1.txt" "$TMP/d2.txt" > "$TMP/merge2.log" 2>&1
ck "0" "$?" "换顺序也能读通"
ck "1" "$(grep -cF '合计：10 次挡回，2 组记录' "$TMP/merge2.log")" "换顺序合计不变"
ck "1" "$(grep -cF '×8  （每份：0/5/3）' "$TMP/merge2.log")" "分布跟着文件顺序走（0/5/3）—— 顺序只改位置，不改总和"

# --top 只截明细
"$DN" --merge "$TMP/d1.txt" "$TMP/d2.txt" "$TMP/d3.txt" --top 1 > "$TMP/merge3.log" 2>&1
ck "0" "$?" "--top 1 也能读通"
ck "1" "$(grep -cF '另有 1 条未列出' "$TMP/merge3.log")" "--top 只截明细并说明"
ck "1" "$(grep -cF '合计：10 次挡回，2 组记录' "$TMP/merge3.log")" "--top 不影响汇总"

# ============================================================================
echo "=== 段三：边界 —— 单份、坏份、互斥、用法 ==="
# ============================================================================
# 单份合并应当与单份读一致（次数一样），只是少了时间窗
"$DN" --merge "$TMP/d1.txt" > "$TMP/m1.log" 2>&1
ck "0" "$?" "只合并一份也能读通"
ck "1" "$(grep -cF '越权账合并：1 份' "$TMP/m1.log")" "一份也报份数"
ck "1" "$(grep -cF '合计：5 次挡回，1 组记录' "$TMP/m1.log")" "一份合并的次数与单份读一致（5）"

# 一份坏就整次不给：半份总账比没有账更危险
cp "$TMP/d1.txt" "$TMP/bad.txt"
sed -i 's/^D 0E00 22 F1B0 3 1 1 00000005/D 0E00 22 F1B0 3 1 1 00000006/' "$TMP/bad.txt"
"$DN" --merge "$TMP/d1.txt" "$TMP/bad.txt" > "$TMP/mbad.log" 2>&1
ck "1" "$?" "一份坏 → 退出 1"
ck "1" "$(grep -cF '越权账合并失败' "$TMP/mbad.log")" "明确报失败而不是给半份结果"
ck "1" "$(grep -cF '2 份里有 1 份读不出来' "$TMP/mbad.log")" "点名几份里坏几份"
ck "0" "$(grep -cF '合计：' "$TMP/mbad.log")" "坏的时候一个合计都不给"

# 两个开关互斥
"$DN" --ledger "$TMP/d1.txt" --merge "$TMP/d2.txt" > "$TMP/mboth.log" 2>&1
ck "2" "$?" "--ledger 与 --merge 同给 → 退出 2"
ck "1" "$(grep -cF '只能选一个' "$TMP/mboth.log")" "并说明为什么不能同时给"

# 用法错
"$DN" --merge > /dev/null 2>&1
ck "2" "$?" "--merge 后面没有文件 → 退出 2"

clean_state
echo ""
echo "通过 $PASS 项，失败 $FAIL 项"
[ "$FAIL" -eq 0 ] || exit 1
