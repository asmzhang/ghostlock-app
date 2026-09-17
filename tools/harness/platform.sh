#!/bin/bash
# 平台适配层 —— windows / darwin / linux 的差异**只允许**出现在本文件。
#
# 为什么单独一层：
#   业务脚本（run.sh / watcher.sh / finish.sh ...）里不应出现 `md5sum`、`timeout`、
#   `stat -c%s` 这类只在某个平台存在的命令，也不应出现 `windows-x86_64` 这种写死的
#   prebuilt 目录名——否则换机/换平台必然要改脚本。全部收敛到这里之后，
#   业务脚本只调用 md5_of / tmo / stat_size / find_ndk / ndk_clang。
#
# 本文件无副作用、不需要设备，可被任何脚本单独 source：
#   source "$(dirname "$0")/platform.sh"
set -u

# ---------------------------------------------------------------- 主机识别
host_os() {
    case "$(uname -s 2>/dev/null)" in
        Darwin)               printf 'darwin\n' ;;
        Linux)                printf 'linux\n' ;;
        MINGW*|MSYS*|CYGWIN*) printf 'windows\n' ;;
        *)                    printf 'unknown\n' ;;
    esac
}
HOST_OS="$(host_os)"

# ---------------------------------------------------------------- 基础命令
require_cmd() { # $1 命令名 $2 提示（可选）
    command -v "$1" >/dev/null 2>&1 && return 0
    printf '[platform] 缺少命令 %s%s\n' "$1" "${2:+ —— $2}" >&2
    return 1
}

md5_of() { # 输出文件 md5（小写十六进制），失败返回非零
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$1" 2>/dev/null | cut -d' ' -f1
    elif command -v md5 >/dev/null 2>&1; then
        md5 -q "$1" 2>/dev/null
    else
        printf '[platform] 既无 md5sum 也无 md5，无法计算校验和\n' >&2
        return 1
    fi
}

stat_size() { # 输出文件字节数
    if stat -c%s "$1" >/dev/null 2>&1; then
        stat -c%s "$1"
    elif stat -f%z "$1" >/dev/null 2>&1; then
        stat -f%z "$1"
    else
        wc -c <"$1" | tr -d ' '
    fi
}

# 超时执行：优先 timeout / gtimeout，都没有时用纯 shell 兜底（macOS 未装 coreutils 也能跑）
TIMEOUT_CMD=""
if command -v timeout  >/dev/null 2>&1; then TIMEOUT_CMD=timeout
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_CMD=gtimeout
fi
export TIMEOUT_CMD

tmo() { # tmo <秒> <命令...>
    local secs=$1; shift
    if [ -n "$TIMEOUT_CMD" ]; then
        "$TIMEOUT_CMD" "$secs" "$@"
        return $?
    fi
    "$@" &
    local pid=$!
    ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) &
    local killer=$!
    wait "$pid" 2>/dev/null
    local rc=$?
    kill "$killer" 2>/dev/null
    return $rc
}

# ---------------------------------------------------------------- Python
# 统一解析解释器：PYTHON（显式覆盖）→ python3 → python。脚本一律用 "$PYTHON_BIN"，
# 不要直接写 python/python3 —— 换机器时两者不一定都存在。
find_python() {
    local c
    for c in "${PYTHON:-}" python3 python; do
        [ -n "$c" ] || continue
        command -v "$c" >/dev/null 2>&1 && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}
PYTHON_BIN="$(find_python || true)"
export PYTHON_BIN

# ---------------------------------------------------------------- Android NDK
# 探测顺序（全部为环境/常规安装位置，**不含任何写死的本机路径**）：
#   ANDROID_NDK_HOME → ANDROID_NDK_ROOT → ANDROID_HOME/ndk/*（取版本最高）
#   → LOCALAPPDATA/Android/Sdk/ndk/* → ~/Android/Sdk/ndk/* → /opt/android-sdk/ndk/*
_ndk_newest() { # 从若干目录中取版本号最高的一个
    local d best="" b
    for d in "$@"; do
        [ -d "$d" ] || continue
        b="$(basename "$d")"
        [ -z "$best" ] && { best="$b"; continue; }
        [ "$(printf '%s\n%s\n' "$best" "$b" | sort -V | tail -1)" = "$b" ] && best="$b"
    done
    [ -n "$best" ] && printf '%s\n' "$best"
}

find_ndk() { # 输出 NDK 根目录；找不到返回非零
    local v
    for v in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
        [ -n "$v" ] && [ -d "$v" ] && { printf '%s\n' "$v"; return 0; }
    done
    local roots=()
    [ -n "${ANDROID_HOME:-}" ] && roots+=("${ANDROID_HOME}/ndk")
    [ -n "${ANDROID_SDK_ROOT:-}" ] && roots+=("${ANDROID_SDK_ROOT}/ndk")
    if [ -n "${LOCALAPPDATA:-}" ]; then
        local la; la="$(printf '%s' "$LOCALAPPDATA" | tr -d '\r' | tr '\\' '/')"
        roots+=("${la}/Android/Sdk/ndk")
    fi
    roots+=("${HOME:-}/Android/Sdk/ndk" "/opt/android-sdk/ndk" "/usr/local/lib/android/sdk/ndk")
    local r
    for r in "${roots[@]}"; do
        [ -d "$r" ] || continue
        local newest
        newest="$(_ndk_newest "$r"/*/)"
        [ -n "$newest" ] && { printf '%s\n' "${r%/}/${newest}"; return 0; }
    done
    return 1
}

ndk_prebuilt_bin() { # $1=NDK 根 → 输出 prebuilt/*/bin（自动识别 windows/darwin/linux，不写死名字）
    local ndk=${1:-} d
    [ -n "$ndk" ] || return 1
    for d in "$ndk"/toolchains/llvm/prebuilt/*/bin; do
        [ -d "$d" ] && { printf '%s\n' "$d"; return 0; }
    done
    return 1
}

ndk_clang() { # $1=NDK 根 $2=API（默认 35）→ 输出 clang 可执行路径（Windows 自动加 .cmd）
    local ndk=${1:-} api=${2:-35} bindir base
    bindir="$(ndk_prebuilt_bin "$ndk")" || return 1
    base="aarch64-linux-android${api}-clang"
    if [ "$HOST_OS" = windows ] && [ -f "${bindir}/${base}.cmd" ]; then
        printf '%s\n' "${bindir}/${base}.cmd"
    elif [ -x "${bindir}/${base}" ]; then
        printf '%s\n' "${bindir}/${base}"
    else
        return 1
    fi
}

export -f host_os require_cmd md5_of stat_size tmo _ndk_newest find_ndk ndk_prebuilt_bin ndk_clang 2>/dev/null || true
