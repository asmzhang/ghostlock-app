#!/bin/bash
# 配置层 —— 把 L0(CLI/env) / L1(harness.local.env) / L3(env.sh 探测) 合并成
# 一个"唯一配置对象"，并做参数校验。
#
# 使用（在 env.sh 之后 source，然后先调用 config_init "$@"）：
#   source env.sh
#   source config.sh
#   config_init "$@" || exit 1
#
# 设计约束：
#   * 本文件**不**探测设备、**不**跑 adb（DEV 的探测在 env.sh），只做配置合并与校验；
#   * 所有输出（尤其 --print-config）不得包含任何本机敏感值以外的推断——它就是要打印真实值，
#     因此**只打印到终端**，不写入仓库文件；
#   * 未知参数一律报错退出，不静默忽略（避免"参数写错但看起来在跑"）。
set -u

CONFIG_LOADED=0
DRY_RUN=0
MODE="${MODE:-tune}"

config_usage() {
    cat <<'EOF'
用法: bash tools/harness/<script>.sh [选项]

通用选项:
  --print-config      打印最终生效的配置（含来源），不执行任何动作
  --dry-run           打印将要执行的设备命令，不真正执行
  --mode <tune|use>   tune=探索并锁参（默认）；use=读已锁定的 gl_tuned.env 复跑
  --device <序列号>   指定设备（等价 GHOSTLOCK_DEV）
  --rounds <N>        TUNE 轮数（等价 ROUNDS）
  --shift <N>         pselect waiter 字偏移（等价 SHIFT）
  -h, --help          显示本帮助

配置来源优先级: 命令行/环境变量 > <REPO>/harness.local.env > 内置默认+自动探测
复制示例开始:   cp config/harness.example.env harness.local.env
EOF
}

config_load_local() {
    local f="${GHOSTLOCK_LOCAL_ENV:-${PROJECT_DIR_POSIX:-.}/harness.local.env}"
    if [ -f "$f" ]; then
        # shellcheck disable=SC1090
        . "$f"
        CONFIG_LOCAL_ENV="$f"
    else
        CONFIG_LOCAL_ENV=""
    fi
}

config_load_tuned() { # MODE=use：读取 TUNE 命中时锁定的参数
    local f="${TUNED:-}"
    [ -n "$f" ] && [ -f "$f" ] || {
        printf '[config] MODE=use 需要 %s（TUNE 命中时会生成），当前不存在。\n' "${f:-<未定义 TUNED>}" >&2
        printf '[config] 先跑一次 TUNE:  bash tools/harness/run.sh\n' >&2
        return 1
    }
    # shellcheck disable=SC1090
    . "$f"        # 提供 SHIFT / CORE / CCORE
    CONFIG_TUNED_ENV="$f"
}

config_defaults() { # L3 内置默认（优先级最低：只在 L0/L1 都没有时生效）
    SHIFT="${SHIFT:--2}"                    # 历史实测只有 -2 会 fire
    ROUNDS="${ROUNDS:-10}"                  # 建议 ≥20（单轮命中率约 5–8%）
    REBOOT_EVERY="${REBOOT_EVERY:-0}"
    GL_SKIP_FIXUP="${GL_SKIP_FIXUP:-1}"
    GL_LAYOUT="${GL_LAYOUT:-A}"
    GL_SELF_W2="${GL_SELF_W2:-1}"
    GL_INSMOD_ONLY="${GL_INSMOD_ONLY:-1}"
    GL_HOLD="${GL_HOLD:-1}"
    export SHIFT ROUNDS REBOOT_EVERY
    export GL_SKIP_FIXUP GL_LAYOUT GL_SELF_W2 GL_INSMOD_ONLY GL_HOLD
}

config_parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --print-config) PRINT_CONFIG=1 ;;
            --dry-run)      DRY_RUN=1 ;;
            -h|--help)      config_usage; exit 0 ;;
            --mode)         MODE="${2:-}"; shift ;;
            --device)       DEV="${2:-}"; GHOSTLOCK_DEV="${2:-}"; shift ;;
            --rounds)       ROUNDS="${2:-}"; shift ;;
            --shift)        SHIFT="${2:-}"; shift ;;
            --) shift; break ;;
            -*) printf '[config] 未知选项: %s（用 --help 查看）\n' "$1" >&2; return 2 ;;
            *)  : ;;   # 位置参数由调用脚本自行处理（如 finish.sh 的包名）
        esac
        shift
    done
    return 0
}

config_ndk_pin() { # 从 deps.manifest 取已验证构建的 NDK 版本（无则空）
    local f="${DEPS_MANIFEST:-}"
    [ -f "$f" ] || return 0
    sed -n 's/^# *build-pin:.*ndk=\([^ ]*\).*/\1/p' "$f" | head -1
}

config_check_ndk_pin() { # NDK 版本偏离已验证构建时给出提示（换版本会改变产物哈希）
    local pin; pin="$(config_ndk_pin)"
    [ -n "$pin" ] || return 0
    [ -n "${CONFIG_NDK:-}" ] || return 0
    local cur; cur="$(basename "$CONFIG_NDK")"
    [ "$cur" = "$pin" ] && return 0
    printf '[config] 提示：当前 NDK=%s，已验证构建用的是 %s —— 产物哈希会不同；\n' "$cur" "$pin" >&2
    printf '[config]       换 NDK 版本后请重跑一轮真机复验（见 config/deps.manifest）。\n' >&2
}

config_validate() {
    local err=0
    case "$MODE" in tune|use) ;; *) printf '[config] MODE 只能是 tune|use，当前=%s\n' "$MODE" >&2; err=1 ;; esac
    case "${ROUNDS:-}" in ''|*[!0-9]*) printf '[config] ROUNDS 必须是正整数，当前=%s\n' "${ROUNDS:-<空>}" >&2; err=1 ;;
        *) [ "$ROUNDS" -ge 1 ] || { printf '[config] ROUNDS 必须 ≥1\n' >&2; err=1; } ;; esac
    case "${SHIFT:-}" in ''|-|*[!0-9-]*) printf '[config] SHIFT 必须是整数，当前=%s\n' "${SHIFT:-<空>}" >&2; err=1 ;; esac
    case "${REBOOT_EVERY:-0}" in ''|*[!0-9]*) printf '[config] REBOOT_EVERY 必须是非负整数\n' >&2; err=1 ;; esac
    for v in CORE CCORE; do
        eval "val=\${$v:-}"
        [ -z "$val" ] && continue
        case "$val" in *[!0-9]*) printf '[config] %s 必须是整数，当前=%s\n' "$v" "$val" >&2; err=1 ;; esac
    done
    if [ -n "${CORE:-}" ] && [ -n "${CCORE:-}" ] && [ "$CORE" = "$CCORE" ]; then
        printf '[config] CORE 与 CCORE 不能相同（竞态需要两个核），当前都是 %s\n' "$CORE" >&2; err=1
    fi
    return $err
}

config_require_device() {
    [ -n "${DEV:-}" ] && return 0
    printf '[config] 未探测到设备。请连接设备，或设置 GHOSTLOCK_DEV=<序列号>（多设备时必须指定）。\n' >&2
    return 1
}

config_dump() { # 打印最终配置与来源
    printf '%-22s %s\n' 'HOST_OS'          "${HOST_OS:-?}"
    printf '%-22s %s\n' 'REPO'             "${PROJECT_DIR_POSIX:-?}"
    printf '%-22s %s\n' 'WORK_DIR'         "${WORK_DIR_POSIX:-?}"
    printf '%-22s %s\n' 'DEPS'             "${DEPS_POSIX:-?}"
    printf '%-22s %s\n' 'DEV'              "${DEV:-<未探测到>}"
    printf '%-22s %s\n' 'TARGET_MODEL'     "${GHOSTLOCK_TARGET_MODEL:-<未设>}"
    printf '%-22s %s\n' 'MODE'             "$MODE"
    printf '%-22s %s\n' 'ROUNDS'           "${ROUNDS:-<空>}"
    printf '%-22s %s\n' 'SHIFT'            "${SHIFT:-<空>}"
    printf '%-22s %s\n' 'CORE/CCORE'       "${CORE:-<自动探测>}/${CCORE:-<自动探测>}"
    printf '%-22s %s\n' 'REBOOT_EVERY'     "${REBOOT_EVERY:-0}"
    printf '%-22s %s\n' 'BIN'              "${BIN:-?}"
    printf '%-22s %s\n' 'KO'               "${KO:-?}"
    printf '%-22s %s\n' 'KSUD'             "${KSUD_BIN:-?}"
    printf '%-22s %s\n' 'TIMEOUT_CMD'      "${TIMEOUT_CMD:-<无，用内建兜底>}"
    printf '%-22s %s\n' 'NDK_ROOT'         "${CONFIG_NDK:-<未找到>}"
    printf '%-22s %s\n' 'CLANG'            "${CONFIG_CLANG:-<未找到>}"
    printf '%-22s %s\n' 'NDK 已验证版本'    "${CONFIG_NDK_PIN:-<未声明>}"
    printf '%-22s %s\n' 'LOCAL_ENV'        "${CONFIG_LOCAL_ENV:-<未使用>}"
    printf '%-22s %s\n' 'TUNED_ENV'        "${CONFIG_TUNED_ENV:-<未使用>}"
    printf '%-22s %s\n' 'DRY_RUN'          "$DRY_RUN"
    printf '%-22s %s\n' 'exploit 开关'      "SKIP_FIXUP=${GL_SKIP_FIXUP:-1} LAYOUT=${GL_LAYOUT:-A} SELF_W2=${GL_SELF_W2:-1} INSMOD_ONLY=${GL_INSMOD_ONLY:-1} HOLD=${GL_HOLD:-1} OWNER=${GL_OWNER:-<空>}"
}

# 把 exploit 开关组装成随 adb shell 下发的环境串（唯一来源，勿在别处硬编码）
config_exploit_env() {
    printf 'GHOSTLOCK_SHIFT=%s GHOSTLOCK_CORE=%s GHOSTLOCK_CONSUMER_CORE=%s' \
        "${SHIFT}" "${CORE}" "${CCORE}"
    printf ' GHOSTLOCK_SKIP_POLICY_FIXUP=%s' "${GL_SKIP_FIXUP:-1}"
    printf ' GHOSTLOCK_LAYOUT=%s'            "${GL_LAYOUT:-A}"
    printf ' GHOSTLOCK_SELF_W2=%s'           "${GL_SELF_W2:-1}"
    printf ' GHOSTLOCK_INSMOD_ONLY=%s'       "${GL_INSMOD_ONLY:-1}"
    printf ' GHOSTLOCK_HOLD=%s'              "${GL_HOLD:-1}"
    printf ' GHOSTLOCK_OWNER=%s'             "${GL_OWNER:-}"
    [ -n "${GL_W1_ATTEMPTS:-}" ] && printf ' GHOSTLOCK_W1_ATTEMPTS=%s' "${GL_W1_ATTEMPTS}"
    [ -n "${GL_KS_VERBOSE:-}" ]  && printf ' GHOSTLOCK_KS_VERBOSE=%s'  "${GL_KS_VERBOSE}"
    :
}

config_init() {
    config_load_local
    config_parse_args "$@" || return $?
    config_defaults
    CONFIG_NDK="$(find_ndk 2>/dev/null || true)"
    CONFIG_CLANG="$(ndk_clang "${CONFIG_NDK:-}" "${API:-35}" 2>/dev/null || true)"
    CONFIG_NDK_PIN="$(config_ndk_pin)"
    [ "${PRINT_CONFIG:-0}" = 1 ] && { config_dump; exit 0; }
    config_check_ndk_pin
    if [ "$MODE" = use ]; then config_load_tuned || return 1; fi
    config_validate || return 1
    CONFIG_LOADED=1
    export MODE DRY_RUN
    return 0
}
