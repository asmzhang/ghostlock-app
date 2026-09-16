#!/usr/bin/env python3
"""把 main.c 里内嵌 shell 的 write_root_script() 整体替换为对 rootscript 模块的调用。

只替换这一个函数体，其余代码逐字节不动。替换前会校验：
  * 能找到 write_root_script 的起点与下一个顶层定义；
  * 该区间内确实包含 snprintf(script, sizeof(script) ...)（证明找对了目标）。
用法：
    python tools/patch_main_rootscript.py          # 执行
    python tools/patch_main_rootscript.py --check  # 只看是否需要替换
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src" / "core" / "main.c"

REPLACEMENT = '''/* 生成 root 脚本。
 *
 * 脚本本体已独立为 src/scripts/root_template.sh，构建期转成 root_template.h 内嵌，
 * 运行期还可被外部模板覆盖。这里只负责取值与落盘 —— 原来 331 行内嵌 shell 的实现
 * 既无法 `bash -n` 也无法单独迭代，且 C 转义极易出错。
 * 取值语义保持不变：仅"1"视为开启，其余一律关闭（烘焙进脚本，因为 setsid worker
 * 链路会丢 environ，实测继承的环境变量不生效）。 */
static void write_root_script(void)
{
  const char *e_skipfix = getenv("GHOSTLOCK_SKIP_POLICY_FIXUP");
  const char *e_insmod = getenv("GHOSTLOCK_INSMOD_ONLY");
  const char *v_skipfix = (e_skipfix && e_skipfix[0] == \'1\') ? "1" : "0";
  const char *v_insmod = (e_insmod && e_insmod[0] == \'1\') ? "1" : "0";

  int n = rootscript_write(g_root_script_path, g_home_dir, v_skipfix, v_insmod);
  if (n < 0) {
    pr_warning("write root script failed path=%s errno=%d\\n",
               g_root_script_path, errno);
    return;
  }
  pr_info("root script written: %d bytes (template=%s)\\n",
          n, rootscript_template_source());
}

'''


def find_span(text: str):
    start = text.find("static void write_root_script(void)")
    if start < 0:
        sys.exit("找不到 write_root_script 定义")
    # 下一个顶层定义（行首的 static/void/int/...）
    nxt = None
    for m in re.finditer(r"^(?:static\s+)?(?:void|int|uintptr_t|long|char|const)\s+\w+",
                         text[start + 10:], re.M):
        nxt = start + 10 + m.start()
        break
    if nxt is None:
        sys.exit("找不到 write_root_script 之后的顶层定义")
    body = text[start:nxt]
    if "snprintf(script, sizeof(script)" not in body and "snprintf(" not in body:
        sys.exit("目标区间不含 snprintf，疑似定位错误，已中止")
    return start, nxt, body


def main():
    text = SRC.read_text(encoding="utf-8", errors="replace")
    start, nxt, body = find_span(text)
    print(f"目标区间: 字符 {start}..{nxt}（{body.count(chr(10))} 行）")

    if "--check" in sys.argv:
        already = "rootscript_write(" in text
        print("已替换" if already else "未替换")
        return 0 if already else 1

    if "rootscript_write(" in body:
        print("该函数已替换过，跳过")
        return 0

    new = text[:start] + REPLACEMENT + text[nxt:]
    SRC.write_text(new, encoding="utf-8", newline="\n")
    print(f"已替换：{len(text)} -> {len(new)} 字符"
          f"（减少 {len(text) - len(new)}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
