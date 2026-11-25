#!/usr/bin/env bash
# =============================================================================
# m15_e2e.sh —— M15 验收：UDS 刷写链路（0x31 擦除 → 0x34 下载 → 0x36 传块 → 0x37 收尾 → 0x31 校验）
#
# 用法： bash tools/m15_e2e.sh [端口]        默认 13474（第二条腿用 端口+1）
#
# 前面 14 个里程碑的每条诊断都是"一问一答"：问 VIN 就得 VIN，问快照就得快照，
# ECU 不需要记住上一个请求。刷写不一样 —— 它是一条有状态的会话：
#   擦除 → 声明"我要传 100 字节" → 一块一块传（每块带 BSC 序号）→ 收尾 → 校验 CRC。
# 中间任何一步乱了（跳号、重发、块超长、没传完就收尾），ECU 必须用**不同的 NRC**
# 说清楚是哪儿错了，而不是笼统地回一个 0x10。这一节验的就是这件事。
#
# 拓扑：网关 + 一台 ECU（0x0003 → 7A0/7A8），ECU 带 --flash。
# 场景由 tools/m15_check.py 驱动 —— 它故意发错，第三方库会把那些错误用法修正掉。
#
# 两条腿：
#   ① 默认块长 34（含 0x36+BSC，数据 32）—— 走完整条链路，含重发与校验；
#   ② --flash-block 10（数据 8）—— 证明"通告的块长真的在卡客户端"：
#      0x74 回 0x000A，同一条脚本把 100 字节切成 13 块，块长再超一个字节就 0x13。
# =============================================================================
set -u

PORT=${1:-13474}
PORT2=$((PORT + 1))
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m15_check.py
SLOG=/tmp/m15_gw.log
ELOG=/tmp/m15_ecu.log
SLOG2=/tmp/m15_gw_b10.log
ELOG2=/tmp/m15_ecu_b10.log
OUT=/tmp/m15_check.txt
OUT2=/tmp/m15_check_b10.txt

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    true
}
trap cleanup EXIT

[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB"; exit 0; }
command -v python3 >/dev/null 2>&1 || { skip "没有 python3"; exit 0; }

IMG_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*37+11)&0xFF for i in range(100)])) & 0xFFFFFFFF))')
IMG2_CRC=$(python3 -c 'import zlib; print("%08X" % (zlib.crc32(bytes([(i*13+7)&0xFF for i in range(8)])) & 0xFFFFFFFF))')

cleanup
echo "=== 1 启动：网关 + 一台带 --flash 的 ECU（块长 34） ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 20 --flash --flash-block 34 --flash-max 65536 \
        > "$ELOG" 2>&1 &
STUB_PID=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 30 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "刷写：0x31 01 FF00/FF01" "$ELOG" \
    && ok "ECU 启动就声明自己在刷写模式（不打开时行为与 M9 一致）" || bad "ECU 启动行没提刷写"
grep -q "通告块长 34 字节（含 0x36+BSC，数据 32）" "$ELOG" \
    && ok "启动行把块长的口径说清楚：34 含 0x36+BSC，数据只有 32" || bad "启动行的块长口径不对"

echo
echo "=== 2 场景（m15_check.py：老服务 → 顺序错 → 参数错 → 擦除 → 下载 → 跳号/重发/超长 → 收尾 → 校验 → 重来） ==="
python3 "$CHECK" "$PORT" 34 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "场景脚本自身 0 失败" || bad "场景脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab VIN_STILL_WORKS)" = "LSVZZ0000B7654321" ] \
    && ok "刷写模式没砸掉老服务：22 F1 86 仍读回原 VIN" || bad "VIN=$(grab VIN_STILL_WORKS)"
[ "$(grab NRC_36_NO_34)" = "24" ]      && ok "没有 0x34 就 0x36 → 0x24（顺序错，不是参数错）" || bad "NRC_36_NO_34=$(grab NRC_36_NO_34)"
[ "$(grab NRC_37_NO_34)" = "24" ]      && ok "没有 0x34 就 0x37 → 0x24" || bad "NRC_37_NO_34=$(grab NRC_37_NO_34)"
[ "$(grab NRC_34_NOT_ERASED)" = "22" ] && ok "没擦除就 0x34 → 0x22（条件不满足）" || bad "NRC_34_NOT_ERASED=$(grab NRC_34_NOT_ERASED)"
[ "$(grab NRC_VERIFY_EMPTY)" = "22" ]  && ok "没有镜像就校验 → 0x22（这是条件不满足，不是校验失败）" || bad "NRC_VERIFY_EMPTY=$(grab NRC_VERIFY_EMPTY)"
[ "$(grab ERASE)" = "7101FF00" ]       && ok "31 01 FF00 → 71 01 FF 00（擦除完成）" || bad "ERASE=$(grab ERASE)"
[ "$(grab NRC_34_DFI)" = "31" ]        && ok "0x34 的 dfi≠0 → 0x31（requestOutOfRange）" || bad "NRC_34_DFI=$(grab NRC_34_DFI)"
[ "$(grab NRC_34_ALFID0)" = "31" ]     && ok "alfid=0x00（0 字节地址/长度）→ 0x31" || bad "NRC_34_ALFID0=$(grab NRC_34_ALFID0)"
[ "$(grab NRC_34_LEN)" = "13" ]        && ok "0x34 的地址/长度段少字节 → 0x13（长度错）" || bad "NRC_34_LEN=$(grab NRC_34_LEN)"
[ "$(grab DOWNLOAD_ACK)" = "74200022" ] && ok "0x34 正响应：74 20 00 22（lengthFormatIdentifier=0x20，块长 2 字节大端）" || bad "DOWNLOAD_ACK=$(grab DOWNLOAD_ACK)"
[ "$(grab MAX_BLOCK_LENGTH)" = "22" ]  && ok "0x74 通告块长 = 0x22 = 34 字节（含 0x36+BSC）" || bad "MAX_BLOCK_LENGTH=$(grab MAX_BLOCK_LENGTH)"
[ "$(grab NRC_36_WRONG_BSC)" = "73" ]  && ok "BSC 跳号（期望 01，发 05）→ 0x73（wrongBlockSequence）" || bad "NRC_36_WRONG_BSC=$(grab NRC_36_WRONG_BSC)"
[ "$(grab BLOCK_1)" = "7601" ]         && ok "第一块 BSC=01 → 76 01（回的是收到的那块 BSC）" || bad "BLOCK_1=$(grab BLOCK_1)"
[ "$(grab BLOCK_1_RETRY)" = "7601" ]   && ok "原样重发同一块 → 仍 76 01（幂等，不报 0x73）" || bad "BLOCK_1_RETRY=$(grab BLOCK_1_RETRY)"
[ "$(grab NRC_36_TOO_LONG)" = "13" ]   && ok "块 35 字节（数据 33）> 通告 34 → 0x13" || bad "NRC_36_TOO_LONG=$(grab NRC_36_TOO_LONG)"
[ "$(grab BLOCK_SEQUENCE)" = "1" ]      && ok "其余各块按 BSC 顺序全部 76 xx" || bad "BLOCK_SEQUENCE=$(grab BLOCK_SEQUENCE)"
[ "$(grab NRC_37_PREMATURE)" = "24" ]  && ok "只传了 2/4 块就 0x37 → 0x24（数据没传完）" || bad "NRC_37_PREMATURE=$(grab NRC_37_PREMATURE)"
[ "$(grab TRANSFER_EXIT)" = "77$IMG_CRC" ] && ok "传完 → 0x77 + CRC（77 $IMG_CRC）" || bad "TRANSFER_EXIT=$(grab TRANSFER_EXIT)"
[ "$(grab EXIT_CRC)" = "$IMG_CRC" ]    && ok "0x77 带回的 CRC-32 = $IMG_CRC（和 tester 自己算的一致）" || bad "EXIT_CRC=$(grab EXIT_CRC)（期望 $IMG_CRC）"
[ "$(grab EXIT_CRC_LEN)" = "5" ]       && ok "0x77 恰好 5 字节：SID + 4 字节 CRC" || bad "EXIT_CRC_LEN=$(grab EXIT_CRC_LEN)"
[ "$(grab NRC_36_AFTER_EXIT)" = "24" ] && ok "收尾之后再传 → 0x24（要重来先 0x34）" || bad "NRC_36_AFTER_EXIT=$(grab NRC_36_AFTER_EXIT)"
[ "$(grab VERIFY_BAD)" = "7101FF0101" ] && ok "错 CRC 校验 → 71 01 FF 01 01（正响应带失败状态，不是否定响应）" || bad "VERIFY_BAD=$(grab VERIFY_BAD)"
[ "$(grab VERIFY_OK)" = "7101FF0100" ]  && ok "对 CRC 校验 → 71 01 FF 01 00（通过）" || bad "VERIFY_OK=$(grab VERIFY_OK)"
[ "$(grab NRC_VERIFY_LEN)" = "13" ]     && ok "只带 2 字节 CRC → 0x13" || bad "NRC_VERIFY_LEN=$(grab NRC_VERIFY_LEN)"
[ "$(grab REF_36)" = "7601" ]          && ok "再刷一遍：擦除清干净状态，8 字节镜像照样跑完" || bad "REF_36=$(grab REF_36)"
[ "$(grab REF_CRC)" = "77$IMG2_CRC" ]  && ok "第二遍 0x77 的 CRC 也对（$IMG2_CRC）" || bad "REF_CRC=$(grab REF_CRC)（期望 77$IMG2_CRC）"

echo
echo "=== 3 等 ECU 退场，核对它的账（状态机到底吃了几块） ==="
# 退场账只在进程结束时打印：等它自然跑完（不猜时间）
wait "$STUB_PID" 2>/dev/null
tail -8 "$ELOG"
got=$(grep -o "收下 [0-9]* 块" "$ELOG" | grep -o "[0-9]*" | head -1)
byt=$(grep -o "镜像 [0-9]* 字节" "$ELOG" | grep -o "[0-9]*" | head -1)
crc=$(grep -o "CRC-32=0x[0-9A-F]*" "$ELOG" | head -1 | cut -d= -f2)
# 账是"最后一次 0x34 起算的会话"：中间那条 100 字节的已经由 0x77 的 CRC 证过了，
# 这里看的是最后重刷的 8 字节那条（1 块 / 8 字节）——重发幂等则靠 0x77 的 CRC 说话
[ "${got:-0}" = "1" ]  && ok "ECU 账：最后一轮收下 1 块（8 字节的短镜像）" || bad "收下 ${got:-?} 块（期望 1）"
[ "${byt:-0}" = "8" ]  && ok "ECU 账：镜像 8 字节（0x34 重新声明长度时镜像也清了）" || bad "镜像 ${byt:-?} 字节（期望 8）"
[ "${crc:-}" = "0x$IMG2_CRC" ] && ok "ECU 自己算的 CRC = 0x$IMG2_CRC（和最后一条 0x77 报的一致）" || bad "CRC=$crc（期望 0x$IMG2_CRC）"

echo
echo "=== 4 第二条腿：--flash-block 10（证明通告的块长真的在卡客户端） ==="
cleanup
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 20 --flash --flash-block 10 --flash-max 65536 \
        > "$ELOG2" 2>&1 &
STUB_PID2=$!
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT2" --seconds 30 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG2" 2>&1 &
sleep 1.2
grep -q "通告块长 10 字节（含 0x36+BSC，数据 8）" "$ELOG2" \
    && ok "启动行跟着 --flash-block 变（10 字节、数据 8）" || bad "小块的启动行不对"

python3 "$CHECK" "$PORT2" 10 > "$OUT2" 2>&1
cat "$OUT2"
grep -q "^FAIL=0$" "$OUT2" && ok "小块腿：脚本自身 0 失败" || bad "小块腿脚本失败"
g2() { grep -m1 "^$1=" "$OUT2" 2>/dev/null | cut -d= -f2; }
[ "$(g2 MAX_BLOCK_LENGTH)" = "0A" ] && ok "0x74 通告块长 = 0x000A（不是写死的 34）" || bad "小块腿 MAX_BLOCK_LENGTH=$(g2 MAX_BLOCK_LENGTH)"
[ "$(g2 DOWNLOAD_ACK)" = "7420000A" ] && ok "小块腿 0x74 正响应：74 20 00 0A" || bad "小块腿 DOWNLOAD_ACK=$(g2 DOWNLOAD_ACK)"
[ "$(g2 BLOCK_SEQUENCE)" = "1" ] && ok "100 字节被切成 13 块，BSC 一路递增全部接受" || bad "小块腿 BLOCK_SEQUENCE=$(g2 BLOCK_SEQUENCE)"

wait "$STUB_PID2" 2>/dev/null
got2=$(grep -o "收下 [0-9]* 块" "$ELOG2" | grep -o "[0-9]*" | head -1)
byt2=$(grep -o "镜像 [0-9]* 字节" "$ELOG2" | grep -o "[0-9]*" | head -1)
[ "${got2:-0}" = "1" ]  && ok "小块腿 ECU 账：最后一轮也是 1 块（同样的 8 字节重刷）" || bad "小块腿收下 ${got2:-?} 块（期望 1）"
[ "${byt2:-0}" = "8" ]  && ok "小块腿 ECU 账：镜像 8 字节" || bad "小块腿镜像 ${byt2:-?} 字节（期望 8）"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M15 全绿 —— 刷写是条有状态的会话：顺序错/长度错/跳号各有各的码，重发幂等，CRC 对得上。"
    exit 0
fi
exit 1
