#!/usr/bin/env bash
# 一键构建 GhostLock APK —— 自动探测并补齐本机缺失的工具链。
#
# 本机构建 App 需要五个条件，任一缺失过去都以难以定位的方式失败（详见各段注释）。
# 这里全部自动化：能探测的探测，能装的自动装，装不了的才报错并给出确切命令。
#
# 用法： bash tools/build_apk.sh [额外的 gradle 参数...]
#   GHOSTLOCK_NO_INSTALL=1   只检查不安装（CI 里用）
set -uo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJ"

NO_INSTALL="${GHOSTLOCK_NO_INSTALL:-}"
info()  { printf '  \033[36m·\033[0m %s\n' "$*"; }
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()   { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# mise 是否可用（本机用它管工具链）
MISE=""
have mise && MISE="$(command -v mise)"

# 在 mise 已安装的版本里挑一个满足前缀的；找不到则安装。
# 用法：ensure_mise_tool <tool> <version-spec> <前缀>
ensure_mise_tool() {
    local tool="$1" spec="$2" prefix="$3" found=""
    if [ -n "$MISE" ]; then
        found="$($MISE where "$tool@$spec" 2>/dev/null)"
        if [ -z "$found" ] || [ ! -d "$found" ]; then
            found=""
            # 退而求其次：在已安装列表里找同前缀的
            local cand
            for cand in $($MISE ls --installed "$tool" 2>/dev/null | awk '{print $2}'); do
                case "$cand" in "$prefix"*) found="$($MISE where "$tool@$cand" 2>/dev/null)"; break ;; esac
            done
        fi
    fi
    if [ -n "$found" ] && [ -d "$found" ]; then
        printf '%s\n' "$found"; return 0
    fi
    if [ -z "$NO_INSTALL" ] && [ -n "$MISE" ]; then
        info "安装 $tool@$spec ..."
        "$MISE" install "$tool@$spec" >/dev/null 2>&1 || true
        found="$($MISE where "$tool@$spec" 2>/dev/null)"
        [ -n "$found" ] && [ -d "$found" ] && { printf '%s\n' "$found"; return 0; }
    fi
    return 1
}

printf '\n\033[1m== 环境探测\033[0m\n'

# ---------------------------------------------------------------- 1. JDK 25
# Gradle daemon 要求 JDK 25（gradle/gradle-daemon-jvm.properties 的 toolchainVersion，
# 上游 updateDaemonJvm 生成）。用 17/21 启动会直接失败。
JDK25=""
if [ -n "${GHOSTLOCK_JDK25:-}" ]; then
    JDK25="$GHOSTLOCK_JDK25"
else
    JDK25="$(ensure_mise_tool java temurin-25.0.4+7.0.LTS temurin-25 || true)"
fi
if [ -n "$JDK25" ] && [ -d "$JDK25" ]; then
    ok "JDK 25   $JDK25"
else
    die "找不到 JDK 25。请装一个：mise install java@temurin-25.0.4+7.0.LTS
     或设置 GHOSTLOCK_JDK25=<路径>"
fi
export JAVA_HOME="$JDK25"

# ---------------------------------------------------------------- 2. JDK 21
# buildSrc 用 jvmToolchain(21)，而 Gradle 不会自动发现 mise 安装的 JDK，
# 必须通过 org.gradle.java.installations.paths 显式告知。
JDK21=""
if [ -n "${GHOSTLOCK_JDK21:-}" ]; then
    JDK21="$GHOSTLOCK_JDK21"
else
    JDK21="$(ensure_mise_tool java 21.0.2 21 || true)"
fi
if [ -n "$JDK21" ] && [ -d "$JDK21" ]; then
    ok "JDK 21   $JDK21（buildSrc 工具链）"
else
    warn "未找到 JDK 21；若 buildSrc 报 languageVersion=21 请 mise install java@21"
    JDK21=""
fi

# ---------------------------------------------------------------- 3. Rust（必须是 GNU 工具链）
# 本机没有 Visual Studio，所以**不能**用 MSVC 工具链：cargo 找不到真正的 linker 时，
# 会回退到 Git Bash 的 GNU `link`（coreutils 的硬链接命令），报
#     link: extra operand '...rcgu.o'
# 环境已修正为 GNU（mise 全局配置 rust = "stable-x86_64-pc-windows-gnu"，
# rustup 默认同为它，且 MSVC 工具链已卸载）。这里只做校验，不再需要临时改 PATH。
if ! cargo -vV 2>/dev/null | grep -qi "windows-gnu"; then
    die "cargo 当前不是 GNU 工具链（$(cargo -vV 2>/dev/null | grep -i '^host' | tr -d '\r')）。
     MSVC 在本机不可用（无 Visual Studio）。修正：
       mise use -g rust@stable-x86_64-pc-windows-gnu
       rustup default stable-x86_64-pc-windows-gnu"
fi
ok "cargo    $(cargo -vV 2>/dev/null | grep -i '^host' | tr -d '\r')"

# Android 交叉编译目标必须装在当前工具链上
if ! rustup target list --installed 2>/dev/null | grep -q aarch64-linux-android; then
    if [ -z "$NO_INSTALL" ]; then
        info "补 Rust target aarch64-linux-android ..."
        rustup target add aarch64-linux-android >/dev/null 2>&1 || true
    fi
fi

# ---------------------------------------------------------------- 4. make
# 项目的 C 部分经 Makefile 构建，本机默认没有 make。
if have make; then
    ok "make     $(make --version 2>/dev/null | head -1)"
else
    MK="$(ensure_mise_tool make 4.4.1 4 || true)"
    if [ -n "$MK" ]; then
        # mise 的 make 装在 Library/bin 下（也可能在 .mise-bins）
        for d in "$MK/Library/bin" "$MK/.mise-bins"; do
            [ -x "$d/make.exe" ] || [ -x "$d/make" ] && { export PATH="$d:$PATH"; break; }
        done
    fi
    if have make; then
        ok "make     $(make --version 2>/dev/null | head -1)"
    else
        die "找不到 make。请装：mise install make"
    fi
fi

# ---------------------------------------------------------------- 5. NDK / SDK
# SDK 定位：ANDROID_HOME / ANDROID_SDK_ROOT → 由 NDK 反推 → 报错提示。
# 不写死任何本机路径；platform.sh 负责跨平台探测。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/harness/platform.sh"
if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
    _ndk="$(find_ndk 2>/dev/null || true)"
    if [ -n "$_ndk" ]; then
        export ANDROID_HOME="$(cd "${_ndk}/../.." && pwd)"   # <sdk>/ndk/<ver> → <sdk>
    fi
fi
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[ -n "$ANDROID_HOME" ] && [ -d "$ANDROID_HOME" ] || die "找不到 Android SDK：请设置 ANDROID_HOME（或 ANDROID_SDK_ROOT）"
[ -d "$ANDROID_HOME/ndk" ] || die "SDK 下没有 ndk/：$ANDROID_HOME"
ok "Android  $ANDROID_HOME"

# ---------------------------------------------------------------- 6. 依赖镜像
# 到 dl.google.com / repo.maven.apache.org 的 TLS 握手会被中断
# （"Remote host terminated the handshake"），需用阿里云镜像。
# 已安装到 Gradle 的用户级自动加载目录 ~/.gradle/init.d/，因此**直接跑 ./gradlew
# 或 IDE 构建也会生效**，这里不再传 --init-script。仅当缺失时给提示。
if [ -f "$HOME/.gradle/init.d/aliyun-mirror.gradle" ]; then
    ok "镜像     ~/.gradle/init.d/aliyun-mirror.gradle（全局生效）"
else
    warn "未装全局镜像（~/.gradle/init.d/aliyun-mirror.gradle），依赖可能下载失败"
    warn "  可执行： mkdir -p ~/.gradle/init.d && cp gradle/aliyun-mirror.gradle ~/.gradle/init.d/"
fi

# ---------------------------------------------------------------- 构建
printf '\n\033[1m== 构建\033[0m\n'
ARGS=("$@" --no-daemon)
# configuration cache 会固化旧环境，环境刚变过时关掉更稳妥
[ "${GHOSTLOCK_USE_CONFIG_CACHE:-}" = "1" ] || ARGS+=(--no-configuration-cache)

./gradlew :app:assembleDebug "${ARGS[@]}"

APK="$(ls -t app/build/outputs/apk/debug/*.apk 2>/dev/null | head -1)"
[ -n "$APK" ] && printf '\n\033[1m== 产物\033[0m\n  %s (%s)\n' "$APK" "$(du -h "$APK" | cut -f1)"
