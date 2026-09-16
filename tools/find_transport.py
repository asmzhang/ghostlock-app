#!/usr/bin/env python3
"""find_transport.py -- search the syscall surface of a kernel image for a call
chain whose attacker-controlled stack buffer can land exactly on a given
kernel-stack depth.

Background (see docs/GHOSTLOCK_AUDIT_2026-09-14.md):
GhostLock needs a *transport* -- a syscall the victim thread can run whose
user-controlled buffer is copied onto the same kernel stack, exactly where the
stale `struct rt_mutex_waiter` used to live.  Whether that is even possible is a
static property of the image:

    depth(object) = sum(frame sizes of the chain down to the holder)
                    - offset of the object inside the holder's frame
    SP_entry is identical for every syscall of a task, so depths are comparable.

We want depth(buffer) == depth(rt_waiter).  `tools/stack_depth.py` computes one
chain; this script enumerates chains and reports the candidates, so the port
stops guessing `PSELECT_WAITER_WORD_SHIFT` / `ZC_DELTA` and instead picks a
transport that provably reaches.

Usage:
  python tools/find_transport.py kernel.elf --syms syms.txt \
      --target 0x2b8 --tolerance 0x40 --depth 4
"""

import argparse
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

SYMS_ENTRY = re.compile(r"^(?P<addr>[0-9a-f]{8,16})\s+(?P<type>\S)\s+(?P<name>\S+)\s*$")
FRAME_SUB = re.compile(r"sub\s+sp,\s+sp,\s+#(0x[0-9a-f]+|\d+)")
FRAME_PUSH = re.compile(r"stp\s+x29,\s+x30,\s+\[sp,\s+#-(0x[0-9a-f]+|\d+)\]!")
SP_ADD = re.compile(r"^\s*[0-9a-f]+:\s+(?:add|mov)\s+x\d+,\s+sp,\s+#(0x[0-9a-f]+|\d+)\s*$")
BL = re.compile(r"<([^>+]+)(?:\+0x[0-9a-f]+)?>\s*$")


def _int(t):
    return int(t, 16) if t.startswith("0x") else int(t)


def load_syms(path):
    table, ordered = {}, []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        m = SYMS_ENTRY.match(line.strip())
        if not m:
            continue
        table[m.group("name")] = int(m.group("addr"), 16)
        ordered.append(int(m.group("addr"), 16))
    ordered.sort()
    return table, ordered


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--syms", required=True)
    ap.add_argument("--objdump", default="llvm-objdump")
    ap.add_argument("--target", required=True, help="depth to hit, e.g. 0x2b8")
    ap.add_argument("--tolerance", default="0x40")
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--min-object", default="0x58",
                    help="minimum controllable bytes at the landing slot")
    args = ap.parse_args()

    elf = Path(args.elf)
    syms, ordered = load_syms(args.syms)

    # One objdump pass over the whole image; splitting per function header is
    # ~100x faster than one subprocess per function.
    print("disassembling (single pass)...", file=sys.stderr)
    dump = subprocess.run(
        [args.objdump, "-d", "--no-show-raw-insn", str(elf)],
        capture_output=True, text=True, errors="ignore").stdout

    cache = {}
    cur = None
    frame = None
    calls, slots = [], []
    header = re.compile(r"^[0-9a-f]+\s+<([^>+]+)>:")

    def flush(name):
        if name is not None:
            cache[name] = (frame, list(calls), sorted(set(slots)))

    for line in dump.splitlines():
        m = header.match(line.strip())
        if m:
            flush(cur)
            cur, frame, calls, slots = m.group(1), None, [], []
            continue
        if cur is None:
            continue
        text = line.split(":", 1)[1].strip() if ":" in line else ""
        if frame is None:
            fm = FRAME_SUB.search(text) or FRAME_PUSH.search(text)
            if fm:
                frame = _int(fm.group(1))
        if "bl" in text and "<" in text:
            bm = BL.search(text.split("bl", 1)[1].strip())
            if bm and bm.group(1) in syms:
                calls.append(bm.group(1))
        sm = SP_ADD.match(line)
        if sm:
            slots.append(_int(sm.group(1)))
    flush(cur)

    def body(name):
        return cache.get(name, (None, [], []))

    target = _int(args.target)
    tol = _int(args.tolerance)
    min_obj = _int(args.min_object)
    roots = sorted(n for n in syms if n.startswith("__arm64_sys_"))
    found = []

    for root in roots:
        # BFS over call chains, accumulating frame sizes
        q = deque([(root, [root], 0)])
        seen = set()
        while q:
            name, chain, acc = q.popleft()
            if len(chain) > args.depth or name in seen:
                continue
            seen.add(name)
            frame, calls, slots = body(name)
            if frame is None:
                continue
            acc += frame
            # a controllable buffer in THIS frame?
            for off in slots:
                depth = acc - off
                if abs(depth - target) <= tol:
                    found.append((abs(depth - target), depth, off, frame, list(chain)))
            for c in calls:
                q.append((c, chain + [c], acc))

    found.sort(key=lambda x: (x[0], x[1]))
    print(f"target depth = 0x{target:x}  (+-0x{tol:x}), min buffer >= 0x{min_obj:x}")
    print(f"candidates: {len(found)}")
    seen_chains = set()
    shown = 0
    for delta, depth, off, frame, chain in found:
        key = (tuple(chain), off)
        if key in seen_chains:
            continue
        seen_chains.add(key)
        gap = depth - target
        print(f"  depth=0x{depth:x} (gap {gap:+#x})  slot sp+0x{off:x} of {chain[-1]}"
              f" (frame 0x{frame:x})")
        print(f"      chain: {' -> '.join(chain)}")
        shown += 1
        if shown >= 40:
            print("  ... (truncated)")
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
