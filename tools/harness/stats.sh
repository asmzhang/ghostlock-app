#!/bin/bash
# 统计 TUNE / SCAN / RETRY 轮次日志的结果分布。
# 日志位置由 env.sh 决定（LOGDIR，默认 WORK_DIR），**不再假设"脚本自身目录"**——
# 这正是它此前失效的原因（WORK_DIR 重构后日志搬到了运行层，且文件名是 gl_tune_r<N>.log）。
set -uo pipefail

_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./env.sh
. "${_dir}/env.sh"

cd "$LOGDIR" || { echo "找不到日志目录：$LOGDIR" >&2; exit 1; }
echo "日志目录：$LOGDIR"

total_r=0; total_hit=0; total_panic=0; total_safe=0
printf "%-24s %6s %5s %6s %6s\n" "log" "rounds" "hit" "panic" "safe"
for f in gl_run*.out harness_run_*.out; do
  [ -f "$f" ] || continue
  r=$(grep -ac "^=== TUNE round\|^=== SCAN\|^=== RETRY" "$f" 2>/dev/null)
  [ "${r:-0}" -eq 0 ] && continue
  h=$(grep -ac "root (uid 0)\|result: SUCCESS\|=== SUCCESS" "$f" 2>/dev/null)
  p=$(grep -ac "result: PANIC" "$f" 2>/dev/null)
  s=$(grep -ac "result: SAFE\|result: NOFIRE" "$f" 2>/dev/null)
  printf "%-24s %6s %5s %6s %6s\n" "$f" "$r" "$h" "$p" "$s"
  total_r=$((total_r+r)); total_hit=$((total_hit+h))
  total_panic=$((total_panic+p)); total_safe=$((total_safe+s))
done
echo "-----------------------------------------------------------"
printf "%-24s %6s %5s %6s %6s\n" "TOTAL" "$total_r" "$total_hit" "$total_panic" "$total_safe"
