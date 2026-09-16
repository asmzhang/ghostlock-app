#!/usr/bin/env python3
"""stack_depth.py -- derive kernel-stack frame geometry from the target's own
kernel binary, so GhostLock's "transport lands on the stale rt_mutex_waiter"
premise can be checked instead of guessed.

Why this exists
---------------
Both GhostLock transports rely on the same idea: the thread that owns the
dangling `task_struct::pi_blocked_on` re-enters the kernel through a *different*
syscall whose attacker-controlled buffer is copied onto the *same* kernel stack,
landing exactly on top of the (already dequeued) `struct rt_mutex_waiter`.

Whether that can happen at all is a pure function of:
  * the call-chain frame sizes of the two syscalls, and
  * the offset of the buffer inside the deepest frame.

All of it is statically readable out of the kernel image:

    SP_entry                      <- identical for every syscall of a task
      - N1                        <- frame of the syscall wrapper
      - N2 ...
      - Nk                        <- frame of the leaf function
      + off_in_leaf               <- the buffer / the waiter

so

    depth(syscall) = sum(frame sizes along the chain) - off_in_leaf

and the transport can only work when `depth(buffer) == depth(waiter)`.
A mismatch of 8 bytes is fatal; a mismatch of 0xa8 is structural.

Frame size is the immediate of the prologue's `sub sp, sp, #imm` (or the
pre-indexed `stp ..., [sp, #-imm]!`), which this script reads out of
llvm-objdump.  Nothing here is guessed.

Usage
-----
  # one function: frame size + all `add xN, sp, #off` slots (candidate locals)
  python tools/stack_depth.py FILE.elf --syms SYMS.txt -f futex_wait_requeue_pi

  # an explicit chain: prints per-hop frames and the running depth
  python tools/stack_depth.py FILE.elf --syms SYMS.txt \
      --chain __arm64_sys_futex,do_futex,futex_wait_requeue_pi \
      --object 0x98

  # a chain without the leaf offset (frame sizes only)
  python tools/stack_depth.py FILE.elf --syms SYMS.txt \
      --chain __arm64_sys_pselect6,core_sys_select
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

SYMS_ENTRY = re.compile(r"^(?P<addr>[0-9a-f]{8,16})\s+(?P<type>\S)\s+(?P<name>\S+)\s*$")
FRAME_SUB = re.compile(r"sub\s+sp,\s+sp,\s+#(0x[0-9a-f]+|\d+)")
FRAME_PUSH = re.compile(r"stp\s+x29,\s*x30,\s+\[sp,\s+#-(0x[0-9a-f]+|\d+)\]!")
SP_ADD = re.compile(r"^\s*[0-9a-f]+:\s+(?:add|mov)\s+(x\d+),\s+sp,\s+#(0x[0-9a-f]+|\d+)\s*$")


def _int(text):
    return int(text, 16) if text.startswith("0x") else int(text)


def load_syms(path):
    """Parse an `llvm-nm`-style dump into {name: (addr, type)} plus a sorted list."""
    table = {}
    ordered = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        m = SYMS_ENTRY.match(line.strip())
        if not m:
            continue
        addr = int(m.group("addr"), 16)
        name = m.group("name")
        table[name] = (addr, m.group("type"))
        ordered.append((addr, name))
    ordered.sort()
    return table, ordered


def disasm(objdump, elf, start, stop, cache):
    key = (start, stop)
    if key in cache:
        return cache[key]
    out = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn",
         f"--start-address={hex(start)}", f"--stop-address={hex(stop)}", str(elf)],
        capture_output=True, text=True, errors="ignore")
    # drop the "file format" banner so the first emitted line is the header
    lines = [ln for ln in out.stdout.splitlines()
             if "<" in ln or re.match(r"^\s*[0-9a-f]+:", ln)]
    cache[key] = lines
    return lines


def next_addr(ordered, addr):
    for i, (a, _) in enumerate(ordered):
        if a == addr:
            return ordered[i + 1][0] if i + 1 < len(ordered) else addr + 0x4000
    return addr + 0x4000


def analyse(objdump, elf, syms, ordered, name, cache):
    """Return (frame_size, [sp_relative_slots]) for `name`."""
    if name not in syms:
        raise SystemExit(f"symbol not found: {name}")
    addr, _ = syms[name]
    lines = disasm(objdump, elf, addr, next_addr(ordered, addr), cache)
    frame = None
    slots = []
    for ln in lines:
        body = ln.split(":", 1)[1].strip() if ":" in ln else ln.strip()
        if frame is None:
            m = FRAME_SUB.search(body) or FRAME_PUSH.search(body)
            if m:
                frame = _int(m.group(1))
        m = SP_ADD.match(ln)
        if m:
            slots.append((int(m.group(1)[1:]), _int(m.group(2))))
    return frame, slots


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf")
    ap.add_argument("--syms", required=True, help="llvm-nm style symbol dump")
    ap.add_argument("--objdump", default="llvm-objdump")
    ap.add_argument("-f", "--function", action="append", default=[],
                    help="analyse one function (repeatable)")
    ap.add_argument("--chain", help="comma-separated call chain, outermost first")
    ap.add_argument("--object", help="hex offset of the object inside the LEAF frame")
    args = ap.parse_args()

    syms, ordered = load_syms(args.syms)
    cache = {}

    if args.function:
        for name in args.function:
            frame, slots = analyse(args.objdump, args.elf, syms, ordered, name, cache)
            print(f"{name}: frame=0x{frame:x}" if frame is not None else f"{name}: no frame")
            for reg, off in slots:
                print(f"    {reg} = sp + 0x{off:x}")

    if args.chain:
        names = [n.strip() for n in args.chain.split(",") if n.strip()]
        depth = 0
        for name in names:
            frame, _ = analyse(args.objdump, args.elf, syms, ordered, name, cache)
            if frame is None:
                raise SystemExit(f"{name}: could not determine frame size")
            depth += frame
            print(f"  +0x{frame:<6x}  {name:<32s} running depth = 0x{depth:x}")
        if args.object:
            obj = _int(args.object)
            total = depth - obj
            print(f"  object at sp+0x{obj:x}: depth(object) = 0x{depth:x} - 0x{obj:x}"
                  f" = 0x{total:x}  ({total} bytes below SP_entry)")
        else:
            print(f"  leaf entry depth = 0x{depth:x}")


if __name__ == "__main__":
    sys.exit(main())
