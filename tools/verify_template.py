#!/usr/bin/env python3
"""回归验证：确认"重构后的模板"与"重构前的内嵌脚本"逐字节等价。

做法
----
重构前 main.c 把 shell 内嵌为 C 字符串；重构后脚本独立为
src/scripts/root_template.sh 并在构建期转成 C 头。这个改写必须是**无损的**，
否则"能编译"没有意义。本工具从 git 里的基线提交取出旧 main.c，
用与 gen_root_template.py 完全相同的规则还原出脚本，再与当前模板比对。

用法
----
    python tools/verify_template.py [基线引用]
默认基线引用：347dfec8fa6cd5c204a693565f7e9fd1482ee6ca（2026-09-11 "root achieved" 提交）。
注：原先默认引用 tag `verified-2026-09-11`，该 tag 已于 2026-09-16 按决策删除，故改用其指向的提交
（tag 对象 cdc5eba 仍在对象库，可用 `git tag -a verified-2026-09-11 347dfec -m "<原消息>"` 重建）。
"""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
CUR = PROJ / "src" / "scripts" / "root_template.sh"

_ESC = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "?": "?"}

SUBS = [
    (re.compile(r"^HOME_DIR='[^']*'$", re.M), "HOME_DIR='@@HOME_DIR@@'"),
    (re.compile(r"^GHOSTLOCK_SKIP_FIXUP_BAKED='[^']*'$", re.M),
     "GHOSTLOCK_SKIP_FIXUP_BAKED='@@SKIP_FIXUP@@'"),
    (re.compile(r"^GHOSTLOCK_INSMOD_ONLY_BAKED='[^']*'$", re.M),
     "GHOSTLOCK_INSMOD_ONLY_BAKED='@@INSMOD_ONLY@@'"),
]


def extract_from_c(text: str) -> str:
    lines = text.split("\n")
    start = next((i for i, l in enumerate(lines) if "script, sizeof(script)," in l), None)
    if start is None:
        sys.exit("旧 main.c 里找不到 snprintf(script, sizeof(script), ...)")
    end = next((j for j in range(start, min(start + 600, len(lines)))
                if "g_home_dir, v_skipfix, v_insmod);" in lines[j]), None)
    if end is None:
        sys.exit("找不到格式参数结尾")

    lit = re.compile(r'^\s*"(.*)",?\s*$')
    parts = []
    for l in lines[start + 1:end + 1]:
        m = lit.match(l)
        if not m:
            continue
        s = m.group(1).replace("%%", "%")
        parts.append(re.sub(r"\\(.)", lambda mo: _ESC.get(mo.group(1), mo.group(1)), s))
    return "".join(parts)


def main():
    ref = sys.argv[1] if len(sys.argv) > 1 else "347dfec8fa6cd5c204a693565f7e9fd1482ee6ca"

    try:
        old_c = subprocess.run(
            ["git", "show", f"{ref}:src/core/main.c"],
            cwd=PROJ, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        sys.exit(f"取基线失败（{ref}）：{e.stderr.strip()[:200]}")

    old = extract_from_c(old_c)
    for pat, repl in SUBS:
        old, n = pat.subn(repl, old)
        if n != 1:
            sys.exit(f"基线占位符替换异常：{n} 处")

    new = CUR.read_text(encoding="utf-8")
    print(f"基线 {ref} 还原: {len(old)} 字符")
    print(f"当前模板      : {len(new)} 字符")

    if old == new:
        print("✅ 逐字节一致 —— 重构无损")
        return 0

    print("❌ 不一致，差异如下（unified diff，前 40 行）：")
    import difflib
    diff = list(difflib.unified_diff(
        old.split("\n"), new.split("\n"),
        fromfile=f"{ref}:内嵌脚本", tofile="root_template.sh", lineterm="", n=1))
    print("\n".join(diff[:40]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
