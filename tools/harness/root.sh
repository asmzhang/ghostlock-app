#!/bin/bash
# 一键 root 编排：自检 → 后台 watcher → TUNE 循环 → 命中即停 → 收尾 → 终验。
#
# 为什么只能说"一键流程"，不能说"一键必成"：
#   本漏洞是两线程时序竞态，单轮命中率约 5–8%，命中是**概率事件**。
#   这一层能一键化的是**流程编排**（前置检查 / 推送 / 循环 / 命中检测 / 收尾 / 验证），
#   不能一键化的是"这一次一定中"——轮数越多越接近必然：
#     30 轮 ≈ 83%，50 轮 ≈ 95%，100 轮 ≈ 99.7%（按 5.8%/轮估算）。
#
# 用法:
#   bash tools/harness/root.sh                    # 轮数沿用配置（内置默认 10；建议 ≥20）
#   bash tools/harness/root.sh --rounds 30        # 实践推荐：30 轮约 83% 命中率
#   bash tools/harness/root.sh --rounds 50        # 更稳：约 95%
#   bash tools/harness/root.sh --no-finish        # 只跑到命中，不自动收尾
#   bash tools/harness/root.sh --skip-preflight   # 跳过依赖自检（默认会跑 deps.sh）
#   bash tools/harness/root.sh --dry-run          # 只打印计划，不碰设备
#
# 退出码: 0=已 root 且终验通过 / 2=轮数用尽未命中 / 3=前置检查失败 / 4=命中但收尾或终验失败
set -uo pipefail

_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./env.sh
. "${_dir}/env.sh"
# shellcheck source=./config.sh
. "${_dir}/config.sh"

AUTO_FINISH=1
SKIP_PREFLIGHT=0
PASSTHRU=()
while [ $# -gt 0 ]; do
    case "$1" in
        --no-finish)     AUTO_FINISH=0 ;;
        --skip-preflight) SKIP_PREFLIGHT=1 ;;
        *)               PASSTHRU+=("$1") ;;
    esac
    shift
done

config_init "${PASSTHRU[@]}" || exit 1
MODE="${MODE:-tune}"
ROUNDS="${ROUNDS:-30}"

STAMP="$(date +%Y%m%d_%H%M%S)"
RUNLOG="${LOGDIR}/root_${STAMP}.log"
WLOG="${LOGDIR}/_watcher.log"
WPID=""

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

cleanup() { [ -n "$WPID" ] && kill "$WPID" 2>/dev/null; }
trap cleanup EXIT

say "1/6 配置"
printf '  MODE=%s  ROUNDS=%s  SHIFT=%s  设备=%s\n' "$MODE" "$ROUNDS" "${SHIFT:-<默认>}" "${DEV:-<未探测>}"
printf '  WORK_DIR=%s\n  BIN=%s\n  日志=%s\n' "$WORK_DIR_POSIX" "$BIN" "$RUNLOG"

if [ "$DRY_RUN" = 1 ]; then
    echo
    echo "--- DRY-RUN：计划（未执行）---"
    echo "  ① deps 自检（可 --skip-preflight 跳过）"
    echo "  ② 后台起 watcher.sh → $WLOG"
    echo "  ③ run.sh --mode $MODE --rounds $ROUNDS → $RUNLOG"
    echo "  ④ 命中后在日志中匹配 '=== SUCCESS (hit'"
    [ "$AUTO_FINISH" = 1 ] && echo "  ⑤ finish.sh（收尾：soft-reboot → boot_completed → 授权表 → 重启管理器）" || echo "  ⑤ 跳过收尾（--no-finish）"
    echo "  ⑥ 终验 su -c id（期望 uid=0 gid=0 context=u:r:magisk:s0）"
    exit 0
fi

say "2/6 前置检查"
require_dev || exit 3
if [ "$SKIP_PREFLIGHT" = 1 ]; then
    echo "  已跳过（--skip-preflight）"
else
    if bash "${_dir}/deps.sh" >"/tmp/_gl_deps.$$" 2>&1; then
        ok "依赖自检通过"
    else
        bad "依赖自检未通过："
        sed 's/^/    /' "/tmp/_gl_deps.$$" | tail -12
        rm -f "/tmp/_gl_deps.$$"
        exit 3
    fi
    rm -f "/tmp/_gl_deps.$$"
fi

say "3/6 启动 watcher（独立盯 /proc/modules，命中即刻记录）"
bash "${_dir}/watcher.sh" >/dev/null 2>&1 &
WPID=$!
sleep 2
ok "watcher pid=$WPID → $WLOG"

say "4/6 跑 TUNE 循环（命中即自动停止；单轮命中率约 5–8%）"
# run.sh 已在命中时 break，这里只负责把它输出落到固定日志、便于事后定位
bash "${_dir}/run.sh" --mode "$MODE" --rounds "$ROUNDS" 2>&1 | tee "$RUNLOG" | grep -E '^(=== |--- |result:|stage )' || true

if grep -q '=== SUCCESS (hit' "$RUNLOG"; then
    HIT_LINE="$(grep -m1 '=== SUCCESS (hit' "$RUNLOG")"
    say "5/6 命中：$HIT_LINE"
    kill "$WPID" 2>/dev/null; WPID=""
    ok "watcher 已停（其日志：$WLOG）"
    if [ "$AUTO_FINISH" = 1 ]; then
        echo "  执行收尾 finish.sh（幂等：无命中/无模块时安全退出）"
        FINLOG="${LOGDIR}/root_${STAMP}_finish.log"
        # 注意：不能把 finish.sh 接进管道后再判状态——管道末尾命令的退出码会顶替它的
        bash "${_dir}/finish.sh" >"$FINLOG" 2>&1
        FIN_RC=$?
        sed 's/^/  /' "$FINLOG" | tail -40
        echo "  （收尾完整输出：$FINLOG）"
        if [ "$FIN_RC" -ne 0 ]; then
            bad "finish.sh 退出码=$FIN_RC，请查看 $FINLOG"
            exit 4
        fi
    else
        echo "  已跳过收尾（--no-finish）；可手动执行：bash tools/harness/finish.sh"
    fi
else
    say "5/6 轮数用尽，未命中"
    grep -c 'result: PANIC' "$RUNLOG" | sed 's/^/  PANIC 轮数: /'
    echo "  这不是失败——是概率事件：可以加大轮数重跑（--rounds 50），或先检查设备新鲜态。"
    exit 2
fi

say "6/6 终验"
ID="$(adb -s "$DEV" shell 'su -c id' 2>&1 | tr -d '\r')"
printf '  %s\n' "$ID"
if printf '%s' "$ID" | grep -q 'uid=0' && printf '%s' "$ID" | grep -q 'u:r:magisk:s0'; then
    ok "root 就绪（uid=0 + u:r:magisk:s0）"
    echo
    echo "  提醒：这是 exploit 形态的 root —— 真机重启会丢，需要时重跑本脚本。"
    exit 0
else
    bad "终验未达标（期望 uid=0 与 u:r:magisk:s0）"
    echo "  排查：$RUNLOG 与 $WLOG；收尾是幂等的，可手动再跑 finish.sh。"
    exit 4
fi
