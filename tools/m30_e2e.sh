#!/usr/bin/env bash
# ============================================================================
# m30_e2e.sh —— M30 端到端：诊断防火墙（按操作分三档）
#
# 段一  开 --enforce-ops，三台诊断仪各持一档（0E00 读 / 0E01 写 / 0E02 刷写）
#       证明：读档写不了、写档刷不了、刷写档能穿到 ECU（33 → 22）
# 段二  对照腿：不开 --enforce-ops，同一台读档诊断仪拿不到 33
# 段三  默认档：开防火墙但不授权，默认读 → 能读不能写
#
# 日志断言：横幅把它们该说的都说清楚（授权表 / 默认档 / 越权怎么办），
#           退账里"放行 N 条、挡回 M 条"按档计数，且每条挡回日志点名 SA。
#
# 用法：bash tools/m30_e2e.sh [port] [port2]
# ============================================================================
set -u
PORT="${1:-13504}"
PORT2="${2:-13505}"
GW=./build/doip-gateway
ECU=./build/stub-ecu
PY=python3
# 所有后台进程都用行缓冲：stdout 重定向到文件时默认是块缓冲，
# 被 pkill 收掉的那一刻，缓冲区里最后几行（横幅、退账）会丢 —— 断言就会假红。
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

# 从 key=value 输出里取值
kv() {
    local file="$1" key="$2"
    sed -n "s/^${key}=//p" "$file" | head -1
}

# 先清三台 ECU：M19 起指纹是持久状态，段一写进去的东西不能让段三继承
clean_state() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    sleep 0.4
}

echo "=== 环境 ==="
grep -q vcan0 /proc/net/dev || { echo "[FAIL] vcan0 不存在"; exit 1; }
die() { echo "[FAIL] $1"; clean_state; exit 1; }
[ -x "$GW" ] || die "没有 $GW"
[ -x "$ECU" ] || die "没有 $ECU"

# ============================================================================
echo "=== 段一：三档真的分开了（防火墙开、每档一台） ==="
# ============================================================================
clean_state
# 3 号 ECU（0x0003）只用来读；6 号 ECU（0x0006）承担"写/刷写"两条腿，
# 所以它必须带 --flash --secure —— 这样 0x10/0x27/0x2E/0x34 到了 ECU 之后
# 由 ECU 自己按真实条件裁定（网关放行 ≠ ECU 同意，这正是 M30 想演示的层次）。
$STD "$ECU" --iface vcan0 --rx 7A0 --tx 7A8 --vin LSVZZ0000B7654321 --hw 02 \
    --battery-mv 12600 --delay-ms 8 --seconds 26 > "$TMP/ecu1.log" 2>&1 &
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 26 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu2.log" 2>&1 &
$STD "$ECU" --iface vcan0 --rx 7B0 --tx 7B8 --vin LSVBB0000B7654321 --hw 04 \
    --battery-mv 11800 --delay-ms 8 --seconds 40 > "$TMP/ecu3.log" 2>&1 &
sleep 1.2

$STD "$GW" --iface vcan0 --port "$PORT" --seconds 18 \
    --route 0x0003:7A0:7A8:仪表 --route 0x0006:18DA00F1:18DAF100:网关ECU \
    --route 0x0007:7B0:7B8:车身 --power-mode 1 \
    --enforce-ops --grant 0E00:read --grant 0E01:write --grant 0E02:flash \
    --default-grant read > "$TMP/gw1.log" 2>&1 &
GW1=$!
sleep 1.0

ck "1" "$(grep -c '诊断防火墙：开' "$TMP/gw1.log")" "横幅写明防火墙开"
ck "1" "$(grep -c 'SA 0x0E00 → 读' "$TMP/gw1.log")" "横幅列出 0x0E00 的档"
ck "1" "$(grep -c 'SA 0x0E01 → 写' "$TMP/gw1.log")" "横幅列出 0x0E01 的档"
ck "1" "$(grep -c 'SA 0x0E02 → 刷写' "$TMP/gw1.log")" "横幅列出 0x0E02 的档"
ck "1" "$(grep -c '默认档：读' "$TMP/gw1.log")" "横幅写明默认档"

$PY "$HERE/m30_check.py" "$PORT" 1 > "$TMP/leg1.log" 2>&1
LEG1=$?
cat "$TMP/leg1.log"

ck "0x10" "$(kv "$TMP/leg1.log" R_ACT)" "读档能激活"
ck "62F190" "$(kv "$TMP/leg1.log" R_VIN)" "读档能读 VIN"
ck "62F186" "$(kv "$TMP/leg1.log" R_SESSION)" "读档能读会话（0x22 是读档）"
ck "7F2E33" "$(kv "$TMP/leg1.log" R_2E_NRC)" "读档写 DID → 7F 2E 33"
ck "7F1033" "$(kv "$TMP/leg1.log" R_10_NRC)" "读档切编程会话 → 7F 10 33"
ck "7F2733" "$(kv "$TMP/leg1.log" R_27_NRC)" "读档要种子 → 7F 27 33"
ck "7F3433" "$(kv "$TMP/leg1.log" R_34_NRC)" "读档请求下载 → 7F 34 33"
ck "7F3933" "$(kv "$TMP/leg1.log" R_39_NRC)" "不认识的服务号 → 7F 39 33（安全默认）"

ck "0x10" "$(kv "$TMP/leg1.log" W_ACT)" "写档能激活"
ck "5002" "$(kv "$TMP/leg1.log" W_10)" "写档能切编程会话"
ck "OK" "$(kv "$TMP/leg1.log" W_UNLOCK)" "写档能解锁"
ck "6EF184" "$(kv "$TMP/leg1.log" W_2E | cut -c1-6)" "写档能写 DID"
ck "7F3433" "$(kv "$TMP/leg1.log" W_34_NRC)" "写档请求下载 → 7F 34 33（刷写高一档）"

ck "0x10" "$(kv "$TMP/leg1.log" F_ACT)" "刷写档能激活"
ck "5002" "$(kv "$TMP/leg1.log" F_10)" "刷写档能切编程会话"
ck "OK" "$(kv "$TMP/leg1.log" F_UNLOCK)" "刷写档能解锁"
ck "6EF184" "$(kv "$TMP/leg1.log" F_2E | cut -c1-6)" "刷写档也能读写（阶梯）"
ck "7F3422" "$(kv "$TMP/leg1.log" F_34_NRC)" "刷写档的 0x34 穿到 ECU（22 不是 33）"

ck "0" "$LEG1" "段一脚本自身全绿"
# 退账是进程退出时打的，而 SIGTERM 不走任何清理路径 —— 所以这里等它自己跑完 18 秒，
# 让"权限：放行 / 挡回"真的落在日志里（这也是老腿里所有退账断言的同一条规矩）。
wait "$GW1" 2>/dev/null
sleep 0.2
ck "0" "$(grep -q '权限挡回：SA 0x0E00' "$TMP/gw1.log"; echo $?)" "挡回日志点名 0x0E00"
ck "0" "$(grep -q '权限挡回：SA 0x0E01' "$TMP/gw1.log"; echo $?)" "挡回日志点名 0x0E01"
ck "0" "$(grep -q '权限挡回：SA 0x0E00 想「写 DID(0x2E)」' "$TMP/gw1.log"; echo $?)" "挡回日志写明它想干什么"
ck "0" "$(grep -q '权限挡回：SA 0x0E00 想「不认识的服务号」' "$TMP/gw1.log"; echo $?)" "不认识的服务号也点名"
# 退账：放行 & 挡回都要有，且三档计数加起来等于挡回总数
DENY_N=$(grep -o '挡回 [0-9]* 条' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
ALLOW_N=$(grep -o '放行 [0-9]* 条' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
READY_N=$(grep -o '要读 [0-9]*' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
WRITEY_N=$(grep -o '要写 [0-9]*' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
FLASHY_N=$(grep -o '要刷写 [0-9]*' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
ck "6" "$DENY_N" "挡回 6 条（读档 5 条 + 写档 1 条）"
ck "14" "$ALLOW_N" "放行 14 条（读 2 + 写 6 + 刷写 6）"
ck "0" "$READY_N" "没有「要读」被挡（读是最低档，谁都够）"
ck "3" "$WRITEY_N" "「要写」被挡 3 条（读档的 2E/10/27）"
ck "3" "$FLASHY_N" "「要刷写」被挡 3 条（读档 34/39 + 写档 34）"
SUM_DENY=$((READY_N + WRITEY_N + FLASHY_N))
ck "$DENY_N" "$SUM_DENY" "三档计数加起来 = 挡回总数"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段二：对照腿 —— 没有这层，读档的人照样能把请求递到 ECU ==="
# ============================================================================
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 30 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu4.log" 2>&1 &
sleep 1.0
$STD "$GW" --iface vcan0 --port "$PORT2" --seconds 30 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 > "$TMP/gw2.log" 2>&1 &
sleep 1.0

ck "1" "$(grep -c '诊断防火墙：关' "$TMP/gw2.log")" "横幅写明防火墙关"
ck "0" "$(grep -q '加 --enforce-ops 才打开' "$TMP/gw2.log"; echo $?)" "横幅写明怎么打开"

$PY "$HERE/m30_check.py" "$PORT2" 2 > "$TMP/leg2.log" 2>&1
LEG2=$?
cat "$TMP/leg2.log"

ck "0x10" "$(kv "$TMP/leg2.log" R_ACT)" "对照腿能激活"
ck "7F2E7F" "$(kv "$TMP/leg2.log" R_2E_NOT33)" "0x2E 拿到的是 ECU 的 7F（不是 33）"
ck "7F2E7F" "$(kv "$TMP/leg2.log" R_2E_ECU)" "0x2E 的 NRC 是 ECU 自己的 0x7F（条件不满足）"
ck "7F347F" "$(kv "$TMP/leg2.log" R_34_NOT33)" "0x34 拿到的是 ECU 的 7F（不是 33）"
ck "7F347F" "$(kv "$TMP/leg2.log" R_34_ECU)" "0x34 的 NRC 是 ECU 自己的 0x7F（没进编程会话，条件不对）"
ck "0" "$LEG2" "段二脚本自身全绿"
ck "0" "$(grep -c '权限挡回' "$TMP/gw2.log")" "关着的时候一条挡回日志都没有"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段三：开防火墙但一台都不授权，默认档兜底 ==="
# ============================================================================
$STD "$ECU" --iface vcan0 --rx 7A0 --tx 7A8 --vin LSVZZ0000B7654321 --hw 02 \
    --battery-mv 12600 --delay-ms 8 --seconds 30 > "$TMP/ecu5.log" 2>&1 &
sleep 1.0
$STD "$GW" --iface vcan0 --port "$PORT" --seconds 30 \
    --route 0x0003:7A0:7A8:仪表 --power-mode 1 \
    --enforce-ops --default-grant read > "$TMP/gw3.log" 2>&1 &
sleep 1.0

ck "1" "$(grep -c '诊断防火墙：开' "$TMP/gw3.log")" "段三防火墙也开着"
ck "0" "$(grep -q '默认档：读' "$TMP/gw3.log"; echo $?)" "横幅写明默认档是读"
ck "0" "$(grep -c 'SA 0x0E' "$TMP/gw3.log")" "没授权任何 SA（表是空的）"

M30_TARGET=0x0003 $PY "$HERE/m30_check.py" "$PORT" 3 > "$TMP/leg3.log" 2>&1
LEG3=$?
cat "$TMP/leg3.log"

ck "0x10" "$(kv "$TMP/leg3.log" R_ACT)" "没授权的人也能激活（M27 管的是认证，这里只管授权）"
ck "62F190" "$(kv "$TMP/leg3.log" R_VIN)" "默认档能读 VIN"
ck "7F2E33" "$(kv "$TMP/leg3.log" R_2E_NRC)" "默认档写不了 DID"
ck "0" "$LEG3" "段三脚本自身全绿"

pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.3

echo ""
echo "通过 $PASS 项，失败 $FAIL 项"
[ "$FAIL" -eq 0 ] || exit 1
