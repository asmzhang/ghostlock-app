#!/usr/bin/env python3
"""Look up symbols in an llvm-nm dump and print offsets relative to a base.

For building kernel offsets entries: the exploit stores every value as an offset
from KIMAGE_VADDR (the image's link base), so addr - base is what goes into
offsets.h.

Usage:
  sym_lookup.py <nm-dump.txt> [--base 0xffffffc008000000] [name ...]
  sym_lookup.py <nm-dump.txt> --grep nfulnl      # substring search
"""
import argparse
import re
import sys

ADDR = re.compile(r"^([0-9a-fA-F]{16})\s+([A-Za-z])\s+(.+?)\s*$")


def load(path):
    out = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ADDR.match(line.rstrip("\n"))
            if m:
                out.setdefault(m.group(3), (int(m.group(1), 16), m.group(2)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("nm")
    ap.add_argument("--base", default="0xffffffc008000000")
    ap.add_argument("--grep", default=None)
    ap.add_argument("names", nargs="*")
    a = ap.parse_args()
    base = int(a.base, 0)
    syms = load(a.nm)
    print("loaded %d symbols from %s" % (len(syms), a.nm))

    if a.grep:
        pat = re.compile(a.grep)
        hits = sorted((n, v) for n, v in syms.items() if pat.search(n))
        print("-- grep %r -> %d hit(s)" % (a.grep, len(hits)))
        for n, (addr, t) in hits[:60]:
            print("  %016x  0x%07x  [%s]  %s" % (addr, addr - base, t, n))
        return

    print("%-30s %-18s %-12s %s" % ("symbol", "address", "off", "type"))
    for n in a.names:
        if n in syms:
            addr, t = syms[n]
            print("%-30s %016x  0x%07x    %s" % (n, addr, addr - base, t))
        else:
            print("%-30s %s" % (n, "-- not found --"))


if __name__ == "__main__":
    main()
