#!/bin/bash
# 统计所有 tune 日志的轮次结果与耗时
# 以脚本所在目录为根（离线工具）
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
total_r=0; total_hit=0; total_panic=0; total_safe=0
printf "%-20s %6s %5s %6s %6s\n" "log" "rounds" "hit" "panic" "safe"
for f in gl_*.out; do
  [ -f "$f" ] || continue
  r=$(grep -ac "^=== TUNE round" "$f" 2>/dev/null)
  [ "$r" -eq 0 ] && continue
  h=$(grep -ac "result: SUCCESS\|=== SUCCESS" "$f" 2>/dev/null)
  p=$(grep -ac "result: PANIC" "$f" 2>/dev/null)
  s=$(grep -ac "result: SAFE\|result: NOFIRE" "$f" 2>/dev/null)
  printf "%-20s %6s %5s %6s %6s\n" "$f" "$r" "$h" "$p" "$s"
  total_r=$((total_r+r)); total_hit=$((total_hit+h)); total_panic=$((total_panic+p)); total_safe=$((total_safe+s))
done
echo "-----------------------------------------------------------"
printf "%-20s %6s %5s %6s %6s\n" "TOTAL" "$total_r" "$total_hit" "$total_panic" "$total_safe"
