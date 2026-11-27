#!/usr/bin/env bash
# =============================================================================
# m29_e2e.sh —— M29 验收：位子 → 真身份（网关位子账 + 对账工具）
#
# 用法： bash tools/m29_e2e.sh [端口A] [端口B]      默认 13502 / 13503
#
# 这一步要立住的判据：
#   · 网关退出时落一份**位子账**（DOIPSLOTS 1，P 行定长 36，末尾 SUM），
#     账上写的是"哪个 SA 在什么时间段占着哪个位子"；
#   · 段一（不撞位子）：对账工具把 ECU 流水的 F2 / F1 还原成 0x0E01 / 0x0E00 ——
#     "可唯一还原 2 条，歧义 0 条"，退出码 0（--strict 也 0）；
#   · 段二（撞位子）：A 断开后 B 拿到同一个 1 号位子，两笔都是 F1 —— 工具必须报
#     "歧义 + 候选"，--strict 退出码 2。**宁可不答，也不猜**；
#   · 不给账（只给 ECU 流水）：一律"查不到"，不是"没问题"。
#
# 三段：一 = 不撞（新能力腿）；二 = 撞（消歧腿）；三 = 空账（对照腿）。
# =============================================================================
set -u

PORT_A=${1:-13502}
PORT_B=${2:-13503}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
AUDIT=$ROOT/build/doip-audit
CHECK=$ROOT/tools/m29_check.py
GLOG_A=/tmp/m29_gw_a.log
GLOG_B=/tmp/m29_gw_b.log
OUT=/tmp/m29_check.txt
SLOTS_A=/tmp/m29_slots_a.txt
SLOTS_B=/tmp/m29_slots_b.txt
SLOTS_EMPTY=/tmp/m29_slots_empty.txt
STORE_A=/tmp/m29_ecu_a.txt
STORE_B=/tmp/m29_ecu_b.txt
AUDIT_OUT=/tmp/m29_audit.txt

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
    pkill -x doip-gateway 2>/dev/null || true
    pkill -x stub-ecu 2>/dev/null || true
    true
}
trap cleanup EXIT

[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE"; exit 0; }
[ -x "$GW" ]     || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
[ -x "$STUB" ]   || { skip "没有 $STUB"; exit 0; }
[ -x "$AUDIT" ]  || { skip "没有 $AUDIT（对账工具）"; exit 0; }
command -v python3 >/dev/null 2>&1 || { skip "没有 python3"; exit 0; }
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m29_check.py 自身编译不过"; exit 1; }

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2-; }

# $1=端口 $2=秒数 $3=账文件 $4=日志 $5=要不要 --stamp-sa(1/0) $6=ECU 盘 $7=再加一台 11 位 ECU(1/0)
start_fleet() {
    local port=$1 secs=$2 slots=$3 log=$4 stamp=${5:-1} store=$6 extra=${7:-0}
    cleanup
    : > "$log"
    rm -f "$slots" "$slots.tmp" "$store" "$store.tmp"
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 18DA00F1 --tx 18DAF100 --rx-mask 1FFFFF00 \
            --vin LSVCC0000C7654321 --hw HW03 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure \
            --key-store "$store" > /tmp/m29_fd.log 2>&1 &
    if [ "$extra" = "1" ]; then
        stdbuf -oL "$STUB" --iface "$IFACE" --rx 7B0 --tx 7B8 \
                --vin LSVBB0000B7654321 --hw HW04 --seconds "$secs" \
                --flash --flash-block 34 --flash-max 65536 --secure > /tmp/m29_b.log 2>&1 &
    fi
    if [ "$stamp" = "1" ]; then
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0006:18DA00F1:18DAF100:ECU_FD \
                --route 0007:7B0:7B8:ECU_B \
                --stamp-sa --slot-ledger "$slots" > "$log" 2>&1 &
    else
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0006:18DA00F1:18DAF100:ECU_FD \
                --route 0007:7B0:7B8:ECU_B \
                --slot-ledger "$slots" > "$log" 2>&1 &
    fi
    sleep 1.5
}

# $1=账文件 ：检查"这份账自己是不是一份合法的账"
check_ledger_shape() {
    local f=$1 tag=$2
    [ -f "$f" ] && ok "$tag 账文件生成了（$f）" || { bad "$tag 账文件没生成"; return; }
    [ "$(head -1 "$f")" = "DOIPSLOTS 1" ] && ok "$tag 版本行是 DOIPSLOTS 1" || bad "$tag 版本行不对"
    local n
    n=$(grep -c '^P ' "$f" || true)
    ok "$tag 账上有 $n 条租约"
    if [ "$n" -gt 0 ]; then
        [ "$(grep '^P ' "$f" | awk '{ print length }' | sort -u)" = "36" ] \
            && ok "$tag P 行都是定长 36 字符" || bad "$tag P 行长度不是 36"
        grep '^P ' "$f" | awk '{ print substr($0, 29, 8) }' | grep -q '^--------$' \
            && ok "$tag 有「还没还」的租约（归还段是 8 个减号，不让定长破）" || true
    fi
    tail -1 "$f" | grep -qE '^SUM [0-9a-f]{16}$' && ok "$tag 末尾有 16 位校验和" || bad "$tag 末尾没有校验和"
}

# =============================================================================
echo "=== 1 段一：不撞位子 —— 位子 1 / 2 一一对应，可唯一还原 ==="
start_fleet "$PORT_A" 16 "$SLOTS_A" "$GLOG_A" 1 "$STORE_A" 1

grep -q "位子账：写到 $SLOTS_A" "$GLOG_A" \
    && ok "横幅把账的路径写在明面上（不是悄悄落盘）" || bad "横幅没报位子账路径"

python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段一脚本自身 0 失败" || bad "段一有失败项"

[ "$(grab J1_WHO)" = "F2" ] && ok "ECU 流水最新一笔是 F2（后到的 0x0E01）" || bad "J1_WHO=$(grab J1_WHO)"
[ "$(grab J2_WHO)" = "F1" ] && ok "上一笔是 F1（先到的 0x0E00）" || bad "J2_WHO=$(grab J2_WHO)"

wait 2>/dev/null
grep -q "位子账：2 条租约（未归还 0" "$GLOG_A" \
    && ok "退账：两条租约都归还了（断开就还不留尾巴）" \
    || bad "退账租约不对：$(grep '位子账：' "$GLOG_A" | tail -1)"

check_ledger_shape "$SLOTS_A" "段一"

"$AUDIT" --key-store "$STORE_A" --slot-ledger "$SLOTS_A" > "$AUDIT_OUT" 2>&1
cat "$AUDIT_OUT"
grep -q "可唯一还原 2 条，歧义 0 条，查不到 0 条" "$AUDIT_OUT" \
    && ok "对账：两笔都唯一还原成 SA（不猜也猜得出来）" || bad "对账结论不对"
grep -q "0x0E01（位子 2）" "$AUDIT_OUT" && ok "最新那笔还原成 0x0E01 / 位子 2" || bad "没还原出 0x0E01"
grep -q "0x0E00（位子 1）" "$AUDIT_OUT" && ok "上一笔还原成 0x0E00 / 位子 1" || bad "没还原出 0x0E00"
"$AUDIT" --key-store "$STORE_A" --slot-ledger "$SLOTS_A" --strict > /dev/null 2>&1
[ $? -eq 0 ] && ok "各段一致 → --strict 退出码 0（CI 可以用它判红）" || bad "--strict 在「无歧义」时也失败了"

# =============================================================================
echo
echo "=== 2 段二：撞位子 —— 同一个 1 号位子先后两台，必须报歧义 ==="
start_fleet "$PORT_B" 16 "$SLOTS_B" "$GLOG_B" 1 "$STORE_B" 0

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段二脚本自身 0 失败" || bad "段二有失败项"

[ "$(grab J1_WHO)" = "F1" ] && [ "$(grab J2_WHO)" = "F1" ] \
    && ok "ECU 侧两笔都是 F1（位子被回收，ECU 分不出来）" || bad "段二的 F1/F1 没成立"
[ "$(grab SAME_WHO)" = "两笔同位子（ECU 侧无法区分，只能靠网关账判歧义）" ] \
    && ok "段二的结论成立：位子是位子，不是人" || bad "SAME_WHO=$(grab SAME_WHO)"

wait 2>/dev/null
grep -q "位子账：2 条租约（未归还 0" "$GLOG_B" \
    && ok "退账：同一台断开两次，记了两条（不合并）" \
    || bad "退账租约不对：$(grep '位子账：' "$GLOG_B" | tail -1)"

grep -q "位子 1（CAN 源地址 0xF1）" "$GLOG_B" && ok "网关日志里两台都拿到位子 1（复用的证据）" \
    || bad "日志里没看到位子 1 被复用"

"$AUDIT" --key-store "$STORE_B" --slot-ledger "$SLOTS_B" > "$AUDIT_OUT" 2>&1
cat "$AUDIT_OUT"
grep -q "可唯一还原 0 条，歧义 2 条" "$AUDIT_OUT" \
    && ok "对账：两笔都判歧义（不挑一个最像的）" || bad "对账没有报歧义"
grep -q "0x0E00 / 0x0E02" "$AUDIT_OUT" && ok "候选清单把两台都列出来（0x0E00 / 0x0E02）" \
    || bad "候选清单不对"
"$AUDIT" --key-store "$STORE_B" --slot-ledger "$SLOTS_B" --strict > /dev/null 2>&1
[ $? -eq 2 ] && ok "--strict 有歧义 → 退出码 2（这条账在 CI 里会判红）" || bad "--strict 没报 2"

# 只给 ECU 流水、不给网关账：一律"查不到"，不是"没问题"
"$AUDIT" --key-store "$STORE_B" > "$AUDIT_OUT" 2>&1
grep -q "可唯一还原 0 条，歧义 0 条，查不到 2 条" "$AUDIT_OUT" \
    && ok "不给账 → 两笔都「查不到」（不假装不知道为没问题）" || bad "缺账时的结论不对"
grep -q "没给（--slot-ledger）" "$AUDIT_OUT" && ok "缺账时明说是「没给账」，不是「账上干净」" \
    || bad "缺账时没说明原因"

# =============================================================================
echo
echo "=== 3 段三：没开 --stamp-sa —— 空账（这次运行根本没有位子这回事）==="
start_fleet "$PORT_B" 6 "$SLOTS_EMPTY" "$GLOG_B" 0 "$STORE_B" 0
wait 2>/dev/null

grep -q "空账：本次没开 --stamp-sa" "$GLOG_B" \
    && ok "退账明说这次是空账（不让对账工具拿不存在的文件去猜）" || bad "空账的说明没打出来"
grep -q "源地址改写：关" "$GLOG_B" && ok "横幅也说清了改写是关的" || bad "横幅没报改写状态"
check_ledger_shape "$SLOTS_EMPTY" "段三"
"$AUDIT" --key-store "$STORE_B" --slot-ledger "$SLOTS_EMPTY" > "$AUDIT_OUT" 2>&1
grep -q "这条账上没有流水" "$AUDIT_OUT" \
    && ok "空账 + 空流水 → 明说「没什么可对」（不硬凑一个结论）" || bad "空账的对账结论不对"

cleanup
rm -f "$STORE_A" "$STORE_B" "$SLOTS_A" "$SLOTS_B" "$SLOTS_EMPTY" \
      "$STORE_A.tmp" "$STORE_B.tmp" "$SLOTS_A.tmp" "$SLOTS_B.tmp" "$SLOTS_EMPTY.tmp"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M29 验收通过"
else
    exit 1
fi
