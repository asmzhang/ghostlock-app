#!/usr/bin/env python3
"""scan_handlers.py -- find every function whose own frame geometry can host the
GhostLock carrier, independent of how it is reached.

Motivation (docs/GHOSTLOCK_AUDIT_2026-09-14.md sections 8.4/8.6):
the transport must place a raw >=0x48-byte user copy at depth 0x2b8.  No syscall
wrapper does that directly, but the generic ioctl path contributes a fixed
prefix:

    __arm64_sys_ioctl (0x40) + do_vfs_ioctl (0xa0) = 0xe0
    ... then do_vfs_ioctl does `br x10` into f_op->unlocked_ioctl

so any handler frame F with a copy destination at sp+off satisfies

    depth = 0xe0 + F - off

and we need depth == 0x2b8, i.e.  F - off == 0x1d8.

This script scans *every* function in the image for `bl <copy_from_user-ish>`
with a resolvable sp-relative destination, and reports those whose F - off lands
in a window around the requested value, so a carrier can be chosen instead of
guessed.  The same machinery works for other prefixes (read/write/fops paths)
by passing --prefix.

Usage:
  python tools/scan_handlers.py kernel.elf --syms syms.txt \
      --prefix 0xe0 --target 0x2b8 --window 0x40
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

SYMS_ENTRY = re.compile(r"^(?P<addr>[0-9a-f]{8,16})\s+(?P<type>\S)\s+(?P<name>\S+)\s*$")
HEADER = re.compile(r"^[0-9a-f]+\s+<([^>+]+)>:")
FRAME_SUB = re.compile(r"sub\s+sp,\s+sp,\s+#(0x[0-9a-f]+|\d+)")
FRAME_PUSH = re.compile(r"stp\s+x29,\s*x30,\s+\[sp,\s+#-(0x[0-9a-f]+|\d+)\]!")
ADD_SP = re.compile(r"add\s+x(\d+),\s*sp,\s*#(0x[0-9a-f]+|\d+)")
MOV_SP = re.compile(r"mov\s+x(\d+),\s*sp\b")
MOV_REG = re.compile(r"mov\s+x(\d+),\s*x(\d+)\b")
CALL = re.compile(r"bl\s+0x[0-9a-f]+\s+<([^>]+)>")
DEST = re.compile(r"^(ldr|ldur|ldar|ldp|mov|movz|movk|add|sub|and|orr|eor|csel|csinc|"
                  r"adrp|mul|ubfx|sbfx|lsr|lsl|asr|clz|rbit|rev|mvn|neg|csneg|csinv|"
                  r"extr|bfi|bfxil|sxtw|uxtw|sxtb|sxth)\s")
COPY_X0 = ("copy_from_user", "__arch_copy_from_user", "copy_struct_from_user",
           "_copy_from_user", "raw_copy_from_user")
COPY_X2 = ("move_addr_to_kernel", "cmsghdr_from_user_compat_to_kern")


def _int(t):
    return int(t, 16) if t.startswith("0x") else int(t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--syms", required=True)
    ap.add_argument("--objdump", default="llvm-objdump")
    ap.add_argument("--prefix", default="0xe0", help="frames before the handler")
    ap.add_argument("--target", default="0x2b8")
    ap.add_argument("--window", default="0x40")
    ap.add_argument("--max-frame", default="0x600")
    ap.add_argument("--regex", default="",
                    help="only consider functions whose name matches this regex "
                         "(useful to audit one family, e.g. 'f2fs_ioc_')")
    args = ap.parse_args()

    syms = {}
    for line in Path(args.syms).read_text(encoding="utf-8", errors="ignore").splitlines():
        m = SYMS_ENTRY.match(line.strip())
        if m:
            syms[m.group("name")] = int(m.group("addr"), 16)

    print("disassembling (single pass)...", file=sys.stderr)
    dump = subprocess.run([args.objdump, "-d", "--no-show-raw-insn", str(args.elf)],
                          capture_output=True, text=True, errors="ignore").stdout

    prefix = _int(args.prefix)
    target = _int(args.target)
    win = _int(args.window)
    max_frame = _int(args.max_frame)
    name_re = re.compile(r"ioctl|unlocked|compat|read|write|set|get|config|sensor|drm|fuse|binder")

    cur, frame, reg, dests = None, None, {}, []
    hits = []

    only = re.compile(args.regex) if args.regex else None

    def flush(name, frame, dests):
        if name is None or frame is None:
            return
        if only is not None and not only.search(name):
            return
        for off, base in dests:
            need = target - prefix          # == F - off
            have = frame - off
            if abs(have - need) <= win:
                hits.append((abs(have - need), name, frame, off, base, prefix + have))

    for line in dump.splitlines():
        m = HEADER.match(line.strip())
        if m:
            flush(cur, frame, dests)
            cur, frame, reg, dests = m.group(1), None, {}, []
            continue
        if cur is None:
            continue
        text = line.split(":", 1)[1].strip() if ":" in line else ""

        if frame is None:
            fm = FRAME_SUB.search(text) or FRAME_PUSH.search(text)
            if fm:
                frame = _int(fm.group(1))
                if frame > max_frame:
                    frame = None  # keep scanning; oversized frames are unusable

        am = ADD_SP.search(text)
        if am:
            reg[f"x{am.group(1)}"] = _int(am.group(2))
        else:
            mm = MOV_SP.search(text)
            if mm:
                reg[f"x{mm.group(1)}"] = 0
            else:
                mr = MOV_REG.match(text)
                if mr:
                    src = reg.get(f"x{mr.group(2)}")
                    if src is None:
                        reg.pop(f"x{mr.group(1)}", None)
                    else:
                        reg[f"x{mr.group(1)}"] = src
                elif DEST.match(text):
                    d = re.match(r"^[a-z]+\s+([wx]\d+)", text)
                    if d:
                        reg.pop(f"x{d.group(1)[1:]}", None)

        cm = CALL.search(text)
        if cm:
            base = cm.group(1).split(".llvm.")[0]
            arg = "x0" if any(k in base for k in COPY_X0) else (
                "x2" if any(k in base for k in COPY_X2) else None)
            if arg and arg in reg and reg[arg] != 0:
                dests.append((reg[arg], base))
    flush(cur, frame, dests)

    hits.sort()
    print(f"prefix=0x{prefix:x} target=0x{target:x}: need F - off == 0x{target - prefix:x}")
    print(f"handler-frame candidates: {len(hits)}")
    for gap, name, frame, off, base, depth in hits:
        tag = " *" if name_re.search(name) else ""
        print(f"  F=0x{frame:<5x} off=sp+0x{off:<4x} depth=0x{depth:<5x} "
              f"(gap {depth - target:+#x}) {name}{tag}   via {base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
