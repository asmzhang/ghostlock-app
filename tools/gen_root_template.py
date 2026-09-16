#!/usr/bin/env python3
"""从 main.c 提取内嵌的 root script，转成独立模板文件。

背景
----
`write_root_script()` 曾把 243 行 shell 以 C 字符串字面量内嵌在 main.c 里：
  * 无法 `bash -n` 校验；
  * 无法单独运行 / 单独迭代；
  * 转义（\\" \\n %% \\? ）极易出错，历史上确实踩过（\\n 被写成 /n、trigraph ??）。
本工具把脚本抽成 `src/scripts/root_template.sh`，运行时变量改用 `@@NAME@@`
占位符（刻意不含 `$` 和反引号，避免与 shell 语法冲突）。

约定
----
只做**无损搬运**：抽取 + 反转义 + 三处变量行换占位符，其余字符逐字节保持一致。
是否无损由 `--verify` 比对生成结果来判定。

用法
----
    python tools/gen_root_template.py            # 生成模板
    python tools/gen_root_template.py --check    # 只比对，不写入
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src" / "core" / "main.c"
OUT = HERE.parent / "src" / "scripts" / "root_template.sh"

# 运行时传入的三个值 -> 占位符（按行精确匹配，避免误伤）
SUBS = [
    (re.compile(r"^HOME_DIR='[^']*'$", re.M),
     "HOME_DIR='@@HOME_DIR@@'"),
    (re.compile(r"^GHOSTLOCK_SKIP_FIXUP_BAKED='[^']*'$", re.M),
     "GHOSTLOCK_SKIP_FIXUP_BAKED='@@SKIP_FIXUP@@'"),
    (re.compile(r"^GHOSTLOCK_INSMOD_ONLY_BAKED='[^']*'$", re.M),
     "GHOSTLOCK_INSMOD_ONLY_BAKED='@@INSMOD_ONLY@@'"),
]

# C 转义 -> 真实字符
_ESC = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "?": "?", "0": "\0"}


def unescape_c(s: str) -> str:
    """还原 C 字符串字面量。格式串里的 %% 代表字面 %，必须一起还原。"""
    s = s.replace("%%", "%")
    return re.sub(r"\\(.)", lambda mo: _ESC.get(mo.group(1), mo.group(1)), s)


def extract():
    lines = SRC.read_text(encoding="utf-8", errors="replace").split("\n")
    start = next((i for i, l in enumerate(lines) if "script, sizeof(script)," in l), None)
    if start is None:
        sys.exit("找不到 snprintf(script, sizeof(script), ...)")

    end = next((j for j in range(start, min(start + 600, len(lines)))
                if "g_home_dir, v_skipfix, v_insmod);" in lines[j]), None)
    if end is None:
        sys.exit("找不到格式参数结尾 g_home_dir, v_skipfix, v_insmod);")

    lit = re.compile(r'^\s*"(.*)",?\s*$')
    parts, skipped = [], []
    for l in lines[start + 1:end + 1]:
        m = lit.match(l)
        if not m:
            if l.strip():
                skipped.append(l.strip())
            continue
        parts.append(unescape_c(m.group(1)))
    return "".join(parts), skipped


def build_template():
    script, skipped = extract()
    tmpl = script
    for pat, repl in SUBS:
        tmpl, n = pat.subn(repl, tmpl)
        if n != 1:
            sys.exit(f"占位符替换失败：期望 1 处，实际 {n} 处 —— "
                     f"脚本开头结构可能已变，请同步更新 SUBS")
    return tmpl, skipped


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return 0

    tmpl, skipped = build_template()

    if "--check" in sys.argv:
        cur = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if cur == tmpl:
            print("模板一致")
            return 0
        print("模板不一致（需重新运行 gen_root_template.py 生成）")
        return 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(tmpl, encoding="utf-8", newline="\n")
    print(f"已生成 {OUT.relative_to(HERE.parent)}  ({len(tmpl)} 字符, {tmpl.count(chr(10))} 行)")
    if skipped:
        print(f"跳过 {len(skipped)} 行非字符串字面量（应为 C 注释）")
        for s in skipped[:3]:
            print(f"    {s[:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
