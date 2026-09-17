#!/bin/bash
# 依赖自足性检查 —— 换机后**先跑它**，确认运行所需文件都在、且与已验证版本一致。
#
# 检查项：
#   ① 依赖目录（DEPS）与运行层（WORK_DIR）在哪
#   ② config/deps.manifest 里每个依赖：存在性 / 字节数 / md5
#   ③ 构建产物 BIN 是否存在（不存在只提示，不算失败——构建是下一步的事）
#   ④ NDK 是否能定位（构建需要；用 platform.sh 的探测）
#
# 用法: bash tools/harness/deps.sh
set -uo pipefail

_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./env.sh
. "${_dir}/env.sh"

fail=0
say() { printf '\n== %s\n' "$*"; }
ok()  { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail+1)); }
warn(){ printf '  \033[33mWARN\033[0m %s\n' "$*"; }

say "目录"
printf '  REPO      %s\n' "$PROJECT_DIR_POSIX"
printf '  WORK_DIR  %s\n' "$WORK_DIR_POSIX"
printf '  DEPS      %s\n' "$DEPS_POSIX"
printf '  LOGDIR    %s\n' "$LOGDIR"

say "依赖清单（$DEPS_MANIFEST）"
if [ ! -f "$DEPS_MANIFEST" ]; then
    warn "清单不存在，跳过逐项校验"
else
    while read -r name size md5 note; do
        case "$name" in ''|\#*) continue ;; esac
        path="${DEPS}/${name}"
        if [ ! -f "$path" ]; then
            bad "缺 $name —— 期望在 $DEPS/（${note:-无说明}）"
            printf '       修复：把 %s 放到 %s，或设置 GHOSTLOCK_DEPS=<所在目录>\n' "$name" "$DEPS"
            continue
        fi
        got_size="$(stat_size "$path")"
        got_md5="$(md5_of "$path")"
        if [ "$got_size" != "$size" ] || [ "$got_md5" != "$md5" ]; then
            bad "$name 与清单不一致（size $got_size/$size，md5 $got_md5/$md5）"
            warn "       若是换了 .ko 版本，请同步更新 $DEPS_MANIFEST 并重跑一轮真机复验"
        else
            ok "$name  ($size 字节, md5 匹配)"
        fi
    done < "$DEPS_MANIFEST"
fi

say "构建产物"
if [ -f "$BIN" ]; then
    ok "$(basename "$BIN")  ($(stat_size "$BIN") 字节, md5 $(md5_of "$BIN"))"
    printf '       提示：已验证构建 md5 见 config/deps.manifest（当前 NDK 不同则产物不同）\n'
else
    warn "还没有 $BIN —— 构建：make ghostlock（需 NDK）"
fi

say "工具链"
ndk="$(find_ndk 2>/dev/null || true)"
if [ -n "$ndk" ]; then
    ok "NDK  $ndk"
    cc="$(ndk_clang "$ndk" "${API:-35}" 2>/dev/null || true)"
    [ -n "$cc" ] && ok "clang $cc" || bad "NDK 里找不到 aarch64-linux-android${API:-35}-clang"
else
    bad "找不到 NDK —— 设 ANDROID_NDK_HOME（或 ANDROID_HOME 指向 SDK 根）"
fi
command -v adb >/dev/null 2>&1 && ok "adb  $(command -v adb)" || bad "PATH 里没有 adb（或设 GHOSTLOCK_ADB=<adb 路径>）"
printf '  超时命令 %s\n' "${TIMEOUT_CMD:-<无，已用内建兜底>}"

say "结果"
if [ "$fail" -eq 0 ]; then
    echo "  全部就绪。下一步：bash tools/harness/run.sh --dry-run 看一眼命令，再去掉 --dry-run 实跑。"
else
    echo "  $fail 项未通过，请按上面的提示处理后再跑。"
fi
exit "$fail"
