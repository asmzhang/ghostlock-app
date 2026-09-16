#!/usr/bin/env bash
# 构建 ghostlock —— 与 Makefile 等价，但不依赖 make（本机未安装）。
# 职责：
#   1) 把 src/scripts/root_template.sh 转成内嵌头 src/core/root_template.h
#   2) 探测 NDK 并编译出 ./ghostlock
# 用法： bash build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

API="${API:-35}"
TARGET_CONFIG="${TARGET_CONFIG:-target.h}"

# ---- 1) 模板 -> 内嵌头（与 Makefile 同一条 sed 规则，保持一致）----
echo "  GEN   src/core/root_template.h"
{
    echo '/* 自动生成，请勿手改；来源 src/scripts/root_template.sh */'
    echo 'static const char root_template[] ='
    # 注意最后一步把 ? 转义成 \?：脚本里的 case pattern 含连续问号，
    # 直接内联进 C 字符串会触发 trigraph 警告（历史上踩过）。
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/?/\\?/g' -e 's/^/"/' -e 's/$/\\n"/' src/scripts/root_template.sh
    echo ';'
} > src/core/root_template.h

# ---- 2) 探测 NDK ----
# 注意：不能简单取版本号最大的那个 NDK —— 实测 29.x 未提供 API 35 的 clang 入口，
# 取最大版本会直接失败。这里遍历候选，选第一个真正含所需编译器的。
#
# 也别写成 CANDIDATES="$(ls ...)" 再靠 set -e 兜底：那个赋值在 ls 失败时会让脚本
# 以 ls 的退出码（2）静默退出，**不打任何原因**，极难定位（踩过）。
# 这里显式判目录存在，并在失败时给出可执行的指引。
SDK_ROOT="${ANDROID_HOME:-${NDK_ROOT:-}}"
# 其次读 local.properties 的 sdk.dir —— Android 项目的标准做法，且该文件已被 .gitignore
# 忽略（本机特定配置不入库）。注意里面是 java properties 转义形式：
#   sdk.dir=D\:\\platform\\Android\\Sdk
if [ -z "$SDK_ROOT" ] && [ -f "$ROOT/local.properties" ]; then
    SDK_ROOT="$(sed -nE 's/^[[:space:]]*sdk\.dir[[:space:]]*=[[:space:]]*(.*)$/\1/p' "$ROOT/local.properties" \
        | head -1 | tr -d '\r' | sed -E 's/\\\\/\\/g; s/\\:/:/g; s|\\|/|g')"
fi
if [ -z "$SDK_ROOT" ] && [ -n "${LOCALAPPDATA:-}" ]; then
    # Git Bash 里 LOCALAPPDATA 是反斜杠形式（<HOME>\...），转成 POSIX 再拼
    SDK_ROOT="$(printf '%s' "$LOCALAPPDATA" | sed -E 's|\\|/|g')/Android/Sdk"
fi
if [ -z "$SDK_ROOT" ] || [ ! -d "$SDK_ROOT" ]; then
    {
        echo "找不到 Android SDK。" >&2
        echo "  按优先级可用：ANDROID_HOME / NDK_ROOT / local.properties 的 sdk.dir" >&2
        echo "  例如： export ANDROID_HOME=D:/platform/Android/Sdk" >&2
        echo "  或在项目根写： sdk.dir=D\\\\:\\\\platform\\\\Android\\\\Sdk" >&2
    }
    exit 1
fi

if [ -n "${NDK_ROOT:-}" ] && [ -d "$NDK_ROOT" ]; then
    CANDIDATES="$NDK_ROOT"
elif [ -d "$SDK_ROOT/ndk" ]; then
    CANDIDATES="$(ls -d "$SDK_ROOT"/ndk/* 2>/dev/null | tr -d '\r' | sort -Vr)"
else
    CANDIDATES=""
fi
[ -z "$CANDIDATES" ] && { echo "SDK 下没有 ndk/：$SDK_ROOT" >&2; exit 1; }

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) PREBUILT=windows-x86_64 ;;
    *)                    PREBUILT=linux-x86_64 ;;
esac

# Git Bash 下必须优先选"无扩展名"的 wrapper：它带执行位，而 .cmd 没有（实测），
# 用 `[ -x ...cmd ]` 判断会全部落空。
CC=""
for cand in $CANDIDATES; do
    base="$cand/toolchains/llvm/prebuilt/$PREBUILT/bin/aarch64-linux-android${API}-clang"
    if [ -x "$base" ]; then
        CC="$base"; NDK_ROOT="$cand"; break
    fi
    if [ -x "$base.cmd" ]; then
        CC="$base.cmd"; NDK_ROOT="$cand"; break
    fi
done
[ -z "$CC" ] && { echo "没有找到提供 API $API 编译器的 NDK（候选：$CANDIDATES）" >&2; exit 1; }

# ---- 3) 编译 ----
SRCS="src/core/main.c src/core/offsets_json.c src/core/util.c src/core/fops.c src/core/rootscript.c src/core/klog.c src/core/kmod.c"
echo "  CC    ghostlock   ($CC)"
# shellcheck disable=SC2086
"$CC" -O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
    -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H="\"${TARGET_CONFIG}\"" \
    -fPIE -pie -pthread -flto \
    $SRCS -o ghostlock

echo "  OK    $ROOT/ghostlock ($(stat -c%s ghostlock) bytes)"
