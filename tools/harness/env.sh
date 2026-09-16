#!/bin/bash
# GhostLock 公共环境 —— harness 下所有脚本 source 本文件。
#
# 两个目录概念（这是本文件存在的首要原因）：
#   PROJECT_DIR  主项目 ghostlock-app：源码、Makefile、构建产物、工具。
#                由本文件位置反推，不写死。
#   WORK_DIR     运行目录：.ko 模块、设备日志、命中统计等运行期产物。
#                默认取主项目的上级目录，可用 GHOSTLOCK_WORK 覆盖。
#
# 为什么不再各自硬编码：
#   * 设备序列号曾硬编码在 5 个脚本里（换设备要改 5 处）；
#   * 工作目录曾以绝对路径写在 9 个脚本共 ~19 处（换目录全崩）。
#   现在设备自动探测、目录由脚本位置反推，且全部可用环境变量覆盖。

# ---------------------------------------------------------------- 路径
_harness_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR_POSIX="$(cd "${_harness_dir}/../.." && pwd)"          # .../ghostlock-app
PROJECT_DIR="$(cd "$PROJECT_DIR_POSIX" && pwd -W 2>/dev/null || printf '%s' "$PROJECT_DIR_POSIX")"

# 工作目录：默认是主项目的上级（.ko 与日志都在那里）
WORK_DIR_POSIX="$(cd "${GHOSTLOCK_WORK:-$(dirname "$PROJECT_DIR_POSIX")}" && pwd)"
WORK_DIR="$(cd "$WORK_DIR_POSIX" && pwd -W 2>/dev/null || printf '%s' "$WORK_DIR_POSIX")"

# ---------------------------------------------------------------- 产物位置
# adb.exe 只认 Windows 盘符路径（D:/...）；POSIX /d/... 会静默 push 失败。
BIN="${GHOSTLOCK_BIN:-${PROJECT_DIR}/ghostlock}"                  # 构建产物
KO="${GHOSTLOCK_KO:-${WORK_DIR}/android12-5.10_kernelpatch.ko}"   # 主模块
KO_ALT="${GHOSTLOCK_KO_ALT:-${WORK_DIR}/apatch_builtin.ko/android12-5.10_kernelpatch.ko}"
KSUD_BIN="${GHOSTLOCK_KSUD:-${WORK_DIR}/libksud.so}"
KSUN_KO="${GHOSTLOCK_KSUN:-${WORK_DIR}/android12-5.10_kernelsu.ko}"
LOGDIR="${GHOSTLOCK_LOGDIR:-${WORK_DIR_POSIX}}"                   # 本机日志落点
TUNED="${LOGDIR}/gl_tuned.env"

# ---------------------------------------------------------------- 设备
# 探测顺序：GHOSTLOCK_DEV > 按型号匹配 > 唯一设备
GHOSTLOCK_TARGET_MODEL="${GHOSTLOCK_TARGET_MODEL:-marble}"

detect_dev() {
    [ -n "${GHOSTLOCK_DEV:-}" ] && { printf '%s\n' "$GHOSTLOCK_DEV"; return 0; }
    local list hit n
    list=$(adb devices -l 2>/dev/null | awk '/[[:space:]]device[[:space:]]/{print}')
    [ -z "$list" ] && return 1
    hit=$(printf '%s\n' "$list" \
        | grep -iE "model:${GHOSTLOCK_TARGET_MODEL}([[:space:]]|$)|device:${GHOSTLOCK_TARGET_MODEL}([[:space:]]|$)" \
        | head -1 | awk '{print $1}')
    if [ -z "$hit" ]; then
        n=$(printf '%s\n' "$list" | wc -l | tr -d ' ')
        [ "$n" -eq 1 ] && hit=$(printf '%s\n' "$list" | awk '{print $1}')
    fi
    [ -z "$hit" ] && return 1
    printf '%s\n' "$hit"
}

DEV="$(detect_dev)" || DEV=""

require_dev() {
    if [ -z "$DEV" ]; then
        echo "[env] 未找到 adb 设备。请连接设备，或设置 GHOSTLOCK_DEV=<序列号>。" >&2
        return 1
    fi
}

# 设备侧路径（集中在此，避免散落各处）
D_TMP=/data/local/tmp
D_SDCARD=/sdcard
D_AP=/data/adb/ap

export DEV PROJECT_DIR PROJECT_DIR_POSIX WORK_DIR WORK_DIR_POSIX
export BIN KO KO_ALT KSUD_BIN KSUN_KO LOGDIR TUNED
export GHOSTLOCK_TARGET_MODEL
export D_TMP D_SDCARD D_AP
