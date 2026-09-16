#!/usr/bin/env python3
"""Find every code reference to a kernel symbol, straight from a raw kernel ELF.

Why this exists
---------------
A kernel Image alone cannot tell you whether an Android vendor hook is *live*:
the hook's tracepoint struct exists in every ACK build, but the callback only
runs if some built-in driver registered one. Registration compiles to an
ADRP+ADD pair that materialises the tracepoint struct's address, so scanning
.text for ADRP+ADD immediates that resolve to that address answers the question
offline, with no root on the device.

Usage
-----
  python tools/elf_xref.py <kernel.elf> <syms.txt> <addr> [<addr> ...]
      addr may be a hex value (0x...) or a symbol name resolved via syms.txt.

  python tools/elf_xref.py k.elf syms.txt __tracepoint_android_vh_rtmutex_waiter_prio

Notes
-----
* Assumes the vmlinux-to-elf layout: a single executable ".kernel" section whose
  sh_addr is the linked VA of _text. Falls back to any SHF_EXECINSTR section.
* Matches three encodings, which cover every way GCC/Clang materialises a
  static address on arm64:
      ADRP xN, target ; ADD  xN, xN, :lo12:target
      ADRP xN, target ; LDR  xN, [xN, :lo12:target]
      ADRP xN, target ; LDRSW/LDR xN, [xN, :lo12:target]
* ADRP pages are 4 KiB, so the search window is the target's page; ADD/LDR
  supply the low 12 bits.
"""

import struct
import sys
import bisect
import os


def load_symbols(path):
    """syms.txt: '<addr> <type> <name>' -> (sorted addr list, parallel names)."""
    addrs, names = [], []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                a = int(parts[0], 16)
            except ValueError:
                continue
            addrs.append(a)
            names.append(parts[2])
    order = sorted(range(len(addrs)), key=lambda i: addrs[i])
    return [addrs[i] for i in order], [names[i] for i in order]


def lookup(sym_addrs, sym_names, addr):
    i = bisect.bisect_right(sym_addrs, addr) - 1
    if i < 0:
        return "?"
    return sym_names[i]


def read_exec_sections(elf):
    """Yield (va_base, file_off, size) for executable sections, via ELF headers."""
    with open(elf, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("not a 64-bit little-endian ELF")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    def sh(i):
        off = e_shoff + i * e_shentsize
        name, typ, flags = struct.unpack_from("<IIQ", data, off)
        addr, offset, size = struct.unpack_from("<QQQ", data, off + 0x10)
        return name, typ, flags, addr, offset, size

    _, _, _, _, str_off, _ = sh(e_shstrndx)

    def sname(n):
        end = data.index(b"\0", str_off + n)
        return data[str_off + n:end].decode("ascii", "replace")

    secs = []
    for i in range(e_shnum):
        name, typ, flags, addr, offset, size = sh(i)
        if not (flags & 0x4) or size == 0:  # SHF_EXECINSTR
            continue
        if typ != 1:  # PROGBITS
            continue
        secs.append((sname(name), addr, offset, size))
    if not secs:
        raise SystemExit("no executable PROGBITS section found")
    return data, secs


def adrp_target(pc, word):
    """Decode ADRP's page target."""
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):  # sign-extend 21 bits
        imm -= 1 << 21
    return ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF


def collect_refs(data, secs):
    """One pass over .text -> {page: [(pc, kind, lo12), ...]}.

    Indexing by page lets many targets share the single pass; decoding 38 MB of
    instructions with struct.unpack_from per word is otherwise the bottleneck.
    """
    refs = {}
    # the ELF tail (section-header/strtab padding) need not be 4-byte aligned
    words = memoryview(data)[: len(data) // 4 * 4].cast("I")
    for name, va, off, size in secs:
        first = off // 4
        count = size // 4
        for i in range(count - 1):
            w0 = words[first + i]
            if (w0 & 0x9F000000) != 0x90000000:  # ADRP
                continue
            pc = va + i * 4
            page = adrp_target(pc, w0)
            w1 = words[first + i + 1]
            kind = None
            imm12 = 0
            if (w1 & 0xFF800000) == 0x91000000:  # ADD (imm), 64-bit
                imm12 = (w1 >> 10) & 0xFFF
                kind = "add"
            elif (w1 & 0xFFC00000) == 0xF9400000:  # LDR (imm), 64-bit
                imm12 = ((w1 >> 10) & 0xFFF) * 8
                kind = "ldr"
            elif (w1 & 0xFFC00000) == 0xB9400000:  # LDR (imm), 32-bit
                imm12 = ((w1 >> 10) & 0xFFF) * 4
                kind = "ldr32"
            if kind is None:
                continue
            refs.setdefault(page, []).append((pc, kind, imm12))
    return refs


def scan(refs, target, limit=64, near=0):
    """Return list of (resolved_addr, pc, kind) for references to target.

    near > 0 additionally accepts references landing in
    [target, target+near], which is what catches a hook's *field* accesses:
    trace_foo() tests &__tracepoint_foo.key (the tracepoint struct + 8), so
    searching for the struct address alone finds nothing.
    """
    base = target & ~0xFFF
    lo_start = target & 0xFFF
    hits = []
    for lo in range(lo_start, lo_start + near + 1):
        page, lo12 = base, lo
        if lo12 >= 0x1000:  # spilled into the next page
            page, lo12 = base + 0x1000, lo12 - 0x1000
        for pc, kind, imm12 in refs.get(page, ()):
            if imm12 != lo12:
                continue
            hits.append((page + lo12, pc, kind))
            if len(hits) >= limit:
                return hits
    return hits


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    near = 0
    for a in sys.argv[1:]:
        if a.startswith("--near="):
            near = int(a.split("=", 1)[1], 0)
    elf, symfile = args[0], args[1]
    sym_addrs, sym_names = ([], [])
    if os.path.exists(symfile):
        sym_addrs, sym_names = load_symbols(symfile)
    data, secs = read_exec_sections(elf)
    print(f"[elf] {elf}  exec sections: " +
          ", ".join(f"{n}@0x{a:x}({s} bytes)" for n, a, _, s in secs))
    refs = collect_refs(data, secs)
    total = sum(len(v) for v in refs.values())
    print(f"[scan] {total} ADRP+ADD/LDR pairs indexed over {len(refs)} pages"
          f"  (near={near:#x})")

    for raw in args[2:]:
        if raw.lower().startswith("0x"):
            target = int(raw, 16)
            label = raw
        else:
            label = raw
            target = None
            for a, n in zip(sym_addrs, sym_names):
                if n == raw:
                    target = a
                    break
            if target is None:
                print(f"[{label}] symbol not found")
                continue
        print(f"\n=== {label} @ 0x{target:x} ===")
        hits = scan(refs, target, near=near)
        if not hits:
            print("  no reference found  ->  nothing in the built-in kernel uses it")
            continue
        for resolved, va, kind in hits:
            fn = lookup(sym_addrs, sym_names, va) if sym_addrs else "?"
            tag = "" if resolved == target else f"  (= target+{resolved - target:#x})"
            print(f"  0x{va:x}  {kind:5s}  in {fn}{tag}")


if __name__ == "__main__":
    main()
