#!/bin/bash
# GhostLock 公共环境 —— harness 下所有脚本 source 本文件。
#
# 三个目录概念（本文件存在的首要原因）：
#   PROJECT_DIR  = <REPO>    源码、Makefile、构建产物、工具（由本文件位置反推，不写死）
#   WORK_DIR     运行层      *.ko / libksud.so / gl_tuned.env / 日志 / 命中证据
#   DEPS         依赖目录    默认 = WORK_DIR，可用 GHOSTLOCK_DEPS 单独指定
#
# WORK_DIR 解析顺序（为"只带仓库换机"设计）：
#   ① GHOSTLOCK_WORK（或 harness.local.env 里同键）
#   ② <REPO> 的上一级若已有依赖（*.ko / libksud.so）→ 用它（兼容旧布局，本机走这条）
#   ③ 否则 <REPO>/run（自动创建）—— 新机器只拷仓库也能跑
#
# 平台差异（timeout/md5sum/stat/NDK 探测）全部在 platform.sh，本文件不出现平台分支。
# 配置优先级见 config.sh；本文件只负责"探测与推导"这层（L3）。

_harness_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./platform.sh
. "${_harness_dir}/platform.sh"

# ---------------------------------------------------------------- 路径
PROJECT_DIR_POSIX="$(cd "${_harness_dir}/../.." && pwd)"          # .../<REPO>
PROJECT_DIR="$(cd "$PROJECT_DIR_POSIX" && pwd -W 2>/dev/null || printf '%s' "$PROJECT_DIR_POSIX")"

# L1 本地配置（不进库）：换机时唯一需要改的文件
LOCAL_ENV_FILE="${GHOSTLOCK_LOCAL_ENV:-${PROJECT_DIR_POSIX}/harness.local.env}"
if [ -f "$LOCAL_ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$LOCAL_ENV_FILE"
fi

_work_parent="$(dirname "$PROJECT_DIR_POSIX")"
if [ -n "${GHOSTLOCK_WORK:-}" ]; then
    WORK_DIR_POSIX="$(cd "$GHOSTLOCK_WORK" && pwd)"
elif [ -f "${_work_parent}/android12-5.10_kernelpatch.ko" ] || [ -f "${_work_parent}/libksud.so" ]; then
    WORK_DIR_POSIX="$(cd "$_work_parent" && pwd)"
else
    WORK_DIR_POSIX="${PROJECT_DIR_POSIX}/run"
    mkdir -p "$WORK_DIR_POSIX"
fi
WORK_DIR="$(cd "$WORK_DIR_POSIX" && pwd -W 2>/dev/null || printf '%s' "$WORK_DIR_POSIX")"

# 依赖目录：*.ko / libksud.so 所在处（默认与运行层同处）
DEPS_POSIX="${GHOSTLOCK_DEPS:-$WORK_DIR_POSIX}"
DEPS="$(cd "$DEPS_POSIX" 2>/dev/null && pwd -W 2>/dev/null || printf '%s' "$DEPS_POSIX")"

# ---------------------------------------------------------------- 产物位置
# adb.exe 只认 Windows 盘符路径（D:/...）；POSIX /d/... 会静默 push 失败。
BIN="${GHOSTLOCK_BIN:-${PROJECT_DIR}/ghostlock}"                  # 构建产物
KO="${GHOSTLOCK_KO:-${DEPS}/android12-5.10_kernelpatch.ko}"       # 主模块
KO_ALT="${GHOSTLOCK_KO_ALT:-${DEPS}/apatch_builtin.ko/android12-5.10_kernelpatch.ko}"
KSUD_BIN="${GHOSTLOCK_KSUD:-${DEPS}/libksud.so}"
KSUN_KO="${GHOSTLOCK_KSUN:-${DEPS}/android12-5.10_kernelsu.ko}"
LOGDIR="${GHOSTLOCK_LOGDIR:-${WORK_DIR_POSIX}}"                   # 本机日志落点
TUNED="${GHOSTLOCK_TUNED:-${LOGDIR}/gl_tuned.env}"

# ---------------------------------------------------------------- 依赖清单（可选）
DEPS_MANIFEST="${GHOSTLOCK_DEPS_MANIFEST:-${PROJECT_DIR_POSIX}/config/deps.manifest}"

# ---------------------------------------------------------------- 设备
# 探测顺序：GHOSTLOCK_DEV > 按型号匹配 > 唯一设备
GHOSTLOCK_TARGET_MODEL="${GHOSTLOCK_TARGET_MODEL:-marble}"

# adb 包装：让所有既有 `adb ...` 调用点无需修改即可切换到指定二进制
ADB_CMD="${ADB:-${GHOSTLOCK_ADB:-adb}}"
adb() { command "$ADB_CMD" "$@"; }

detect_dev() {
    [ -n "${GHOSTLOCK_DEV:-}" ] && { printf '%s\n' "$GHOSTLOCK_DEV"; return 0; }
    require_cmd "$ADB_CMD" "装 platform-tools 或设 GHOSTLOCK_ADB=<adb 路径>" >/dev/null 2>&1 || return 1
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

# ---------------------------------------------------------------- 设备侧路径
# 集中在此，避免散落各处；均可用环境变量覆盖（不同机型/ROM 可能不一致）。
D_TMP="${GHOSTLOCK_D_TMP:-/data/local/tmp}"
D_SDCARD="${GHOSTLOCK_D_SDCARD:-/sdcard}"
D_AP="${GHOSTLOCK_D_AP:-/data/adb/ap}"
D_KSU="${GHOSTLOCK_D_KSU:-/data/adb/ksu}"

export DEV PROJECT_DIR PROJECT_DIR_POSIX WORK_DIR WORK_DIR_POSIX DEPS DEPS_POSIX
export BIN KO KO_ALT KSUD_BIN KSUN_KO LOGDIR TUNED DEPS_MANIFEST
export GHOSTLOCK_TARGET_MODEL ADB_CMD
export D_TMP D_SDCARD D_AP D_KSU
export HOST_OS TIMEOUT_CMD
export -f adb 2>/dev/null || true
