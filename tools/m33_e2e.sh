#!/usr/bin/env bash
# ============================================================================
# m33_e2e.sh —— M33 端到端：越权账（挡回能落盘、能读回、能被统计）
#
# 段一  三种原因里落两种（请求侧）：
#       读档连撞 12 次 22 F1B0 → 账里一条 ×12（十进制 00000012，不是十六进制 18）
#       读档发 2E F184 / 31 01 02 03 → 账里两条"服务号档不够"
#       写档读 22 F1B0 → 账里另一条（同一对象、不同 SA、不同"有的档"）
#       退账应报「4 条记录，合计 15 次」；落盘后 D 行应是 4 条
# 段二  落第三种（响应侧）：只开 --did-guard-resp，读档读 F184 两次、F1B0 一次
#       → 退账「2 条记录，合计 3 次」，原因是"响应被挡（数据没出去）"
# 段三  工具：doip-deny 读两份账 → 合计/按人/按物/明细；--top 只截明细；
#       改一位 → 退出 1（坏账不"差不多就行"）；空账 → 退出 0 且给结论
#
# 关键断言：`00000012` 这一格必须是十进制。M33 第一步就踩了这个坑 ——
#   text() 用 %08llu 写十进制，parse() 曾用 parseHex 读回，10 次读成 16、37 读成 55。
#   单测 F 组钉住了它，这里再从"落盘 → doip-deny 显示 ×12"整条链路钉一遍。
#
# 用法：bash tools/m33_e2e.sh [port] [port2]
# ============================================================================
set -u
PORT="${1:-13510}"
PORT2="${2:-13511}"
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

kv() {
    local file="$1" key="$2"
    sed -n "s/^${key}=//p" "$file" | head -1
}

clean_state() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    sleep 0.4
}

echo "=== 环境 ==="
[ -d /sys/class/net/vcan0 ] || { echo "[FAIL] vcan0 不存在"; exit 1; }
die() { echo "[FAIL] $1"; clean_state; exit 1; }
[ -x "$GW" ] || die "没有 $GW"
[ -x "$ECU" ] || die "没有 $ECU"
[ -x "$DN" ] || die "没有 $DN"

# ============================================================================
echo "=== 段一：请求侧撞墙 —— 12 次试探合成一条，次数是十进制 ==="
# ============================================================================
clean_state
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 28 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu1.log" 2>&1 &
sleep 1.2
$STD "$GW" --iface vcan0 --port "$PORT" --seconds 20 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --grant 0E01:write --grant 0E02:flash --default-grant read \
    --did-guard --did-default guarded --did F190:open --did F1B0:secret \
    --deny-ledger "$TMP/deny1.txt" > "$TMP/gw1.log" 2>&1 &
GW1=$!
sleep 1.0

ck "1" "$(grep -cF '越权账：写到' "$TMP/gw1.log")" "横幅写明越权账要落盘"

$PY "$HERE/m33_check.py" "$PORT" 1 > "$TMP/leg1.log" 2>&1
LEG1=$?
cat "$TMP/leg1.log"

ck "0x10" "$(kv "$TMP/leg1.log" R_ACT)" "读档能激活"
ck "12" "$(kv "$TMP/leg1.log" R_F1B0_33_TIMES)" "连撞 12 次都回 7F 22 33"
ck "7F2233" "$(kv "$TMP/leg1.log" R_F1B0_LAST)" "第 12 次的响应仍是 7F 22 33"
ck "7F2E33" "$(kv "$TMP/leg1.log" R_2E_NRC)" "读档发 0x2E → 7F 2E 33（服务号档不够）"
ck "7F3133" "$(kv "$TMP/leg1.log" R_31_NRC)" "读档发 0x31 → 7F 31 33（刷写档才够）"
ck "0x10" "$(kv "$TMP/leg1.log" W_ACT)" "写档能激活"
ck "7F2233" "$(kv "$TMP/leg1.log" W_F1B0_NRC)" "写档读钥匙表仍是 7F 22 33（刷写档才够）"
ck "0" "$LEG1" "段一脚本自身全绿"

wait "$GW1" 2>/dev/null
sleep 0.2

# 退账：12 次合成一条，加上 0x2E / 0x31 / 写档那条 = 4 条、15 次
ck "4" "$(sed -n 's/.*越权账：\([0-9]*\) 条记录.*/\1/p' "$TMP/gw1.log" | head -1)" "退账：4 条记录"
ck "15" "$(sed -n 's/.*合计 \([0-9]*\) 次挡回.*/\1/p' "$TMP/gw1.log" | head -1)" "退账：合计 15 次挡回"
ck "1" "$(grep -cF '最常被试探：SA 0x0E00 想 0x22 / DID 0xF1B0（钥匙表）（DID 级别不够）×12' "$TMP/gw1.log")" \
    "退账：点名谁撞得最狠（0x0E00 撞 F1B0 ×12）"
ck "1" "$(grep -cF '越权账已写入' "$TMP/gw1.log")" "退账：账落盘了"

# 账文件本身
ck "DOIPDENY 1" "$(sed -n 1p "$TMP/deny1.txt")" "账文件头是 DOIPDENY 1"
ck "4" "$(grep -c '^D ' "$TMP/deny1.txt")" "账里有 4 条 D 行"
ck "1" "$(grep -c '^SUM ' "$TMP/deny1.txt")" "账末尾有 SUM"
ck "1" "$(grep -cF 'D 0E00 22 F1B0 3 1 1 00000012' "$TMP/deny1.txt")" \
    "12 次写成十进制 00000012（写成 0000000C 才算错）"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段二：响应侧撞墙 —— 落第三种原因（数据差点漏出去） ==="
# ============================================================================
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 24 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu2.log" 2>&1 &
sleep 1.2
$STD "$GW" --iface vcan0 --port "$PORT2" --seconds 16 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --default-grant read \
    --did-guard-resp --did-default guarded --did F190:open --did F184:guarded --did F1B0:secret \
    --deny-ledger "$TMP/deny2.txt" > "$TMP/gw2.log" 2>&1 &
GW2=$!
sleep 1.0

ck "1" "$(grep -cF '越权账：写到' "$TMP/gw2.log")" "段二横幅：响应侧也记账"

$PY "$HERE/m33_check.py" "$PORT2" 2 > "$TMP/leg2.log" 2>&1
LEG2=$?
cat "$TMP/leg2.log"

ck "0x10" "$(kv "$TMP/leg2.log" R_ACT)" "读档能激活"
ck "62F190" "$(kv "$TMP/leg2.log" R_F190)" "公开 DID 照旧能读（62 F190 出来）"
ck "2" "$(kv "$TMP/leg2.log" R_F184_TIMEOUT_TIMES)" "读档读指纹两次都被响应侧挡 → 超时"
ck "TIMEOUT" "$(kv "$TMP/leg2.log" R_F1B0_TIMEOUT)" "读档读钥匙表也被挡 → 超时"
ck "0" "$LEG2" "段二脚本自身全绿"

wait "$GW2" 2>/dev/null
sleep 0.2
ck "2" "$(sed -n 's/.*越权账：\([0-9]*\) 条记录.*/\1/p' "$TMP/gw2.log" | head -1)" "退账：2 条记录"
ck "3" "$(sed -n 's/.*合计 \([0-9]*\) 次挡回.*/\1/p' "$TMP/gw2.log" | head -1)" "退账：合计 3 次挡回"
ck "1" "$(grep -cF 'D 0E00 62 F184 2 1 2' "$TMP/deny2.txt")" "账里存的是响应侧 SID 0x62 + 原因码 2（机器格式只存码，名字在查询时给）"
ck "1" "$(grep -cF '越权账已写入' "$TMP/gw2.log")" "段二账也落盘了"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段三：事后查询 —— doip-deny 读账（按人/按物/明细） ==="
# ============================================================================
"$DN" --ledger "$TMP/deny1.txt" > "$TMP/d1.log" 2>&1
D1=$?
cat "$TMP/d1.log"

ck "0" "$D1" "工具读通（退出码 0）"
ck "1" "$(grep -cF '合计：15 次挡回，4 条记录' "$TMP/d1.log")" "合计：15 次 / 4 条"
ck "1" "$(grep -cF '  0x0E00：14 次' "$TMP/d1.log")" "按 SA：0x0E00 撞了 14 次（排第一）"
ck "1" "$(grep -cF '  0x0E01：1 次' "$TMP/d1.log")" "按 SA：0x0E01 只撞了 1 次"
ck "1" "$(grep -cF 'DID 0xF1B0（钥匙表）：13 次' "$TMP/d1.log")" "按对象：钥匙表被试探 13 次"
ck "1" "$(grep -cF '非 DID 请求（0x2E/0x34/0x31…）：2 次' "$TMP/d1.log")" \
    "按对象：非 DID 的服务号请求 2 次（0x2E + 0x31）"
ck "1" "$(grep -cF '×12' "$TMP/d1.log")" "明细里显示 ×12（十进制读回没虚高成 ×18）"
ck "2" "$(grep -cF '服务号档不够' "$TMP/d1.log")" "明细里点名原因：服务号档不够"
ck "4" "$(grep -cF '本次运行第' "$TMP/d1.log")" "明细里报时间窗用'本次运行'口径"

"$DN" --ledger "$TMP/deny1.txt" --top 2 > "$TMP/d1t.log" 2>&1
ck "0" "$?" "--top 2 也能读通"
ck "1" "$(grep -cF '另有 2 条未列出' "$TMP/d1t.log")" "--top 只截明细，并说明还有几条"
ck "1" "$(grep -cF '合计：15 次挡回，4 条记录' "$TMP/d1t.log")" "--top 不影响汇总（仍是全量）"

"$DN" --ledger "$TMP/deny2.txt" > "$TMP/d2.log" 2>&1
ck "0" "$?" "段二的账也能读通"
ck "2" "$(grep -cF '响应被挡（数据没出去）' "$TMP/d2.log")" "段二账里挂着响应侧的原因"
ck "1" "$(grep -cF 'DID 0xF184（指纹）：2 次' "$TMP/d2.log")" "段二按对象：指纹 2 次"

# 坏账：改一位数字，SUM 立刻对不上 —— 坏账不"差不多就行"
cp "$TMP/deny1.txt" "$TMP/bad.txt"
sed -i 's/^D 0E00 22 F1B0 3 1 1 00000012/D 0E00 22 F1B0 3 1 1 00000013/' "$TMP/bad.txt"
"$DN" --ledger "$TMP/bad.txt" > "$TMP/dbad.log" 2>&1
ck "1" "$?" "改一位 → 退出 1"
ck "1" "$(grep -cF '越权账读不出来' "$TMP/dbad.log")" "坏账给出明确理由而不是猜"

# 空账：一次都没挡，也是正常结论（不能报成"文件坏了"）
EMPTY_SUM=$($PY -c "import hashlib;print(hashlib.sha256(b'DOIPDENY 1\n').hexdigest()[:16])")
printf 'DOIPDENY 1\nSUM %s\n' "$EMPTY_SUM" > "$TMP/empty.txt"
"$DN" --ledger "$TMP/empty.txt" > "$TMP/dempty.log" 2>&1
ck "0" "$?" "空账：退出 0"
ck "1" "$(grep -cF '本次运行没有挡回任何请求' "$TMP/dempty.log")" "空账：给结论，不报坏"

# 用法不对
"$DN" > /dev/null 2>&1
ck "2" "$?" "不给 --ledger → 退出 2（用法错，不是坏账）"

clean_state
echo ""
echo "通过 $PASS 项，失败 $FAIL 项"
[ "$FAIL" -eq 0 ] || exit 1
