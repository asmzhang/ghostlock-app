#!/usr/bin/env python3
"""读候选 handler 里每个 copy_from_user 调用点的 (目标, 长度)。

用法: python tools/copy_len.py <elf> <syms.txt> <func> [<func> ...]

对每个函数:
  - 取帧大小 (sub sp, sp, #imm)
  - 找所有 `bl <...copy_from_user...>` 调用点
  - 回溯到上一个调用/分支为止, 打印设置 x0/x1/x2 的指令
从而读出: 目标是否是 sp 相对栈局部、长度是多少。
"""
import re
import subprocess
import sys

# 必须用 llvm-mingw 那份: NDK 自带的不支持 --start-address。
# 直接用 PATH 上的名字 (与 tools/stack_depth.py 一致); 若 PATH 里没有, 改成
# "D:/platform/llvm-mingw/bin/llvm-objdump.exe" (Windows 形式, Python 不认 /d/... 这种 POSIX 路径)。
OBJDUMP = "llvm-objdump"
SYMS_ENTRY = re.compile(r"^(?P<addr>[0-9a-f]{8,16})\s+(?P<type>\S)\s+(?P<name>\S+)$")
COPY = re.compile(r"bl\s+0x[0-9a-f]+\s+<([^>]*(?:copy_from_user|copy_struct_from_user|copy_to_user)[^>]*)>")
FRAME = re.compile(r"sub\s+sp,\s+sp,\s+#(0x[0-9a-f]+)")
SETS = re.compile(r"\b(?:add|mov|movz|movk|orr|ldr)\s+(x0|x1|x2|w2)\b")


def load_syms(path):
    t = {}
    for line in open(path, encoding="utf-8", errors="ignore"):
        m = SYMS_ENTRY.match(line.strip())
        if m:
            t.setdefault(m.group("name"), int(m.group("addr"), 16))
    return t


def main():
    elf, syms_path = sys.argv[1], sys.argv[2]
    funcs = sys.argv[3:]
    syms = load_syms(syms_path)
    for fn in funcs:
        addr = syms.get(fn)
        print("=" * 70)
        print(f"### {fn}  @ {hex(addr) if addr else 'NOT FOUND'}")
        if addr is None:
            continue
        out = subprocess.run(
            [OBJDUMP, "-d", "--no-show-raw-insn",
             f"--start-address={hex(addr)}", f"--stop-address={hex(addr + 0x600)}", elf],
            capture_output=True, text=True, errors="ignore").stdout
        # 只保留本函数的指令: 第一个 "<name>:" 表头开始收, 第二个表头停。
        # (objdump 在最前面还有 "file format"/"Disassembly of section" banner,
        #  早期版本误把它们当表头, 结果 body 恒空。)
        trimmed, started = [], False
        for l in out.splitlines():
            if re.match(r"^[0-9a-f]+\s+<", l):
                if started:
                    break
                started = True
                continue
            if started:
                trimmed.append(l)
        body = [l.split(":", 1)[1].strip() for l in trimmed
                if re.match(r"^\s*[0-9a-f]+:", l)]

        for l in body[:6]:
            if FRAME.search(l):
                print("  frame:", FRAME.search(l).group(1))
        idx = [i for i, l in enumerate(body) if COPY.search(l)]
        if not idx:
            print("  (no copy_from_user call found in first 0x600 bytes)")
        for i in idx:
            name = COPY.search(body[i]).group(1)
            print(f"  ---- {name}  @insn#{i}")
            j = i - 1
            shown = 0
            while j >= 0 and shown < 12:
                t = body[j]
                if re.match(r"^(bl|b|cbz|cbnz|tbz|tbnz|ret)\b", t) and shown > 0:
                    break
                if SETS.search(t):
                    print("      ", t)
                    shown += 1
                j -= 1


if __name__ == "__main__":
    main()
