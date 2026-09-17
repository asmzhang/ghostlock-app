#!/bin/bash
# 独立轮询设备，而不是轮询 gl_tune.sh 的输出。
# 原因：gl_tune.sh 的 `timeout N adb shell "./ghostlock"` 会一直阻塞到 ghostlock
# 退出；而 ghostlock 在 HOLD 期间会活 320 秒，等它退出时设备早已重启，
# 之前每次"命中后检查"都因此报 device not found。
# 这个 watcher 直接盯设备的 /proc/modules：模块一出现就立刻验证。
# 设备与路径来自 env.sh（自动探测 + 以脚本目录为根）
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
require_dev || exit 1
LOG="${LOGDIR}/_watcher.log"
OUT="${LOGDIR}/harvest_hit"
mkdir -p "$OUT"
: > "$LOG"
echo "watcher start $(date +%H:%M:%S) — polling /proc/modules directly" >> "$LOG"

for i in $(seq 1 1600); do
  mod=$(tmo 8 adb -s $DEV shell "grep -c kernelpatch /proc/modules 2>/dev/null" 2>/dev/null | tr -d '\r')
  if [ "$mod" = "1" ]; then
    echo "[$(date +%H:%M:%S)] *** MODULE DETECTED in /proc/modules ***" >> "$LOG"
    echo "--- su -c id (kpatch sucompat) ---" >> "$LOG"
    tmo 25 adb -s $DEV shell "su -c id 2>&1 | head -3" >> "$LOG" 2>&1
    echo "--- /proc/modules entry ---" >> "$LOG"
    tmo 15 adb -s $DEV shell "grep kernelpatch /proc/modules" >> "$LOG" 2>&1
    echo "--- /sdcard/ghostlock_klog ---" >> "$LOG"
    tmo 15 adb -s $DEV shell "cat $D_SDCARD/ghostlock_klog 2>/dev/null | tail -20" >> "$LOG" 2>&1
    echo "--- kpatch sysfs ---" >> "$LOG"
    tmo 15 adb -s $DEV shell "ls -la /sys/module/kernelpatch 2>&1 | head -3" >> "$LOG" 2>&1
    echo "--- APatch manager ---" >> "$LOG"
    tmo 20 adb -s $DEV shell "pm list packages 2>/dev/null | grep -i apatch; ls -la /data/adb/ap/ 2>&1 | head -5" >> "$LOG" 2>&1
    tmo 15 adb -s $DEV pull /sdcard/ghostlock_klog "$OUT/klog_live.txt" >/dev/null 2>&1
    echo "[$(date +%H:%M:%S)] verification recorded; tracking module residency" >> "$LOG"
    for j in $(seq 1 20); do
      sleep 5
      m2=$(tmo 8 adb -s $DEV shell "grep -c kernelpatch /proc/modules 2>/dev/null" 2>/dev/null | tr -d '\r')
      s2=$(tmo 10 adb -s $DEV shell "su -c id 2>&1 | head -1" 2>/dev/null | tr -d '\r')
      echo "[$(date +%H:%M:%S)] loaded=${m2:-?} su=[${s2:-}]" >> "$LOG"
    done
    exit 0
  fi
  sleep 3
done
echo "watcher timeout $(date +%H:%M:%S)" >> "$LOG"
