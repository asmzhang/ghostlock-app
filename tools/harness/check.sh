#!/bin/bash
# 统一离线验证入口 —— 一条命令跑完全部不需要设备的检查。
#
# 为什么需要：编译、脚本语法、模板无损、ko 符号预检原先散在四处，
# 全靠人记，漏跑一次就可能把坏改动提交上去。这里把它们收敛成一个入口。
#
# 全部检查都是**离线**的：不碰设备，秒级返回，适合提交前跑。
# 用法： bash tools/harness/check.sh
set -uo pipefail

HARNESS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(cd "$HARNESS/../.." && pwd)"
. "$HARNESS/platform.sh"   # 跨平台 stat_size/md5_of 等
cd "$PROJ"

PY="${PYTHON:-${PYTHON_BIN:-}}"      # 平台层已解析（PYTHON 显式覆盖 > python3 > python）
if [ -z "$PY" ]; then
    echo "找不到 python 解释器：请装 python3，或设 PYTHON=<解释器路径>" >&2
    exit 1
fi

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
head_() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------- 1. 构建
head_ "1. 编译（NDK，零警告）"
if out=$(bash build.sh 2>&1); then
    warn=$(printf '%s\n' "$out" | grep -c "warning:") || warn=0
    size=$(stat_size ghostlock 2>/dev/null || echo '?')
    if [ "${warn:-0}" -eq 0 ]; then
        ok "构建通过，${size} 字节，无警告"
    else
        bad "构建有 ${warn} 条警告"
        printf '%s\n' "$out" | grep "warning:" | head -5 | sed 's/^/       /'
    fi
else
    bad "构建失败"
    printf '%s\n' "$out" | tail -12 | sed 's/^/       /'
fi

# ---------------------------------------------------------------- 2. 脚本语法
head_ "2. 全部 shell 脚本 bash -n"
for f in build.sh "$HARNESS"/*.sh; do
    [ -f "$f" ] || continue
    if bash -n "$f" 2>/dev/null; then
        ok "$(basename "$f")"
    else
        bad "$(basename "$f")"
        bash -n "$f" 2>&1 | head -3 | sed 's/^/       /'
    fi
done

# ---------------------------------------------------------------- 3. 模板语法
head_ "3. root 脚本模板语法（独立校验 —— 这是解耦的核心收益）"
if [ -f src/scripts/root_template.sh ]; then
    if bash -n src/scripts/root_template.sh 2>/dev/null; then
        ok "src/scripts/root_template.sh"
    else
        bad "root_template.sh 语法错误"
    fi
    # 占位符必须齐全，否则运行期替换会漏
    miss=0
    for ph in '@@HOME_DIR@@' '@@SKIP_FIXUP@@' '@@INSMOD_ONLY@@'; do
        grep -q "$ph" src/scripts/root_template.sh || { bad "缺占位符 $ph"; miss=1; }
    done
    [ "$miss" = "0" ] && ok "三个占位符齐全"
else
    bad "找不到 root_template.sh"
fi

# ---------------------------------------------------------------- 4. 模板无损
head_ "4. 模板与重构前基线是否逐字节一致"
if [ -n "$PY" ]; then
    if out=$("$PY" tools/verify_template.py 2>&1); then
        ok "$(printf '%s\n' "$out" | tail -1)"
    else
        bad "模板与基线不一致"
        printf '%s\n' "$out" | tail -12 | sed 's/^/       /'
    fi
else
    printf '  \033[33mSKIP\033[0m 未找到 python，跳过\n'
fi

# ---------------------------------------------------------------- 5. ko 符号预检
head_ "5. kernelpatch.ko 的未定义符号是否都在设备 kallsyms 中"
if [ -f "$HARNESS/preflight.sh" ]; then
    if out=$(bash "$HARNESS/preflight.sh" 2>&1); then
        miss=$(printf '%s\n' "$out" | grep -oE 'NOT in device kallsyms: [0-9]+' | grep -oE '[0-9]+' | sort -u | tr '\n' ' ')
        if printf '%s' "$miss" | grep -qvE '^0* ?$'; then
            bad "有符号缺失：$miss"
        else
            ok "全部已解析（缺失计数均为 0）"
        fi
    else
        printf '  \033[33mSKIP\033[0m preflight 未执行成功（可能缺 kallsyms 快照）\n'
    fi
else
    printf '  \033[33mSKIP\033[0m 没有 preflight.sh\n'
fi

# ---------------------------------------------------------------- 6. 生成物未被跟踪
head_ "6. 构建产物不应入库"
if git ls-files --error-unmatch src/core/root_template.h >/dev/null 2>&1; then
    bad "root_template.h 被 git 跟踪了（应加入 .gitignore）"
else
    ok "root_template.h 未被跟踪"
fi
if git ls-files --error-unmatch ghostlock >/dev/null 2>&1; then
    bad "ghostlock 二进制被 git 跟踪了"
else
    ok "ghostlock 二进制未被跟踪"
fi

# ---------------------------------------------------------------- 汇总
printf '\n\033[1m== 汇总\033[0m\n'
printf '  PASS=%d  FAIL=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && printf '  \033[32m全部通过\033[0m\n' || printf '  \033[31m有失败项，请勿提交\033[0m\n'
exit $((fail > 0))
