#!/usr/bin/env python3
"""Dump struct layouts straight out of the kernel Image's embedded BTF.

The vivo 5.15.178 Image carries a real .BTF blob:
    __start_BTF = 0xffffffc00a2c9874 -> file off 0x22c9874 (magic 0xeb9f)
    __stop_BTF  = 0xffffffc00a84cecb
Exploit constants (STRUCT_OFFSETS_5_15, FAKE_TASK_*, p0 offsets) were derived
from a *transcribed* GKI offset table. This reads the device's own BTF instead,
so every field offset is ground truth for the binary that is actually running.

Usage:
  btf_dump.py list <substr>              # type names containing substr
  btf_dump.py show task_struct [--all]   # member offsets (bytes)
  btf_dump.py member task_struct pi_lock
"""
import os
import struct
import sys

# 素材路径不写进仓库：用环境变量 VIVO_IMAGE 指定内核 Image。
# <REFS_DIR> 等占位符的含义见 ASSETS_INDEX.md「占位符约定」一节。
IMAGE = os.environ.get(
    "VIVO_IMAGE",
    "<REFS_DIR>/vivo/Image-5.15.178-android13-8-00005-g14ee4828e57f-ab13224150_A13-era",
)
BTF_VA = 0xFFFFFFC00A2C9874
TEXT_VA = 0xFFFFFFC008000000
BTF_FILE = None  # set by --btf <file>: read a raw BTF blob instead of the Image

KIND = {1: "INT", 2: "PTR", 3: "ARRAY", 4: "STRUCT", 5: "UNION", 6: "ENUM",
        7: "FWD", 8: "TYPEDEF", 9: "VOLATILE", 10: "CONST", 11: "RESTRICT",
        12: "FUNC", 13: "FUNC_PROTO", 14: "VAR", 15: "DATASEC", 16: "FLOAT",
        17: "DECL_TAG", 18: "TYPE_TAG", 19: "ENUM64"}


def load_btf():
    """Read a BTF blob.

    Two sources:
      * --btf <file>  a raw BTF blob (e.g. adb exec-out cat /sys/kernel/btf/vmlinux,
                      or a kernel image with an embedded .BTF that we locate by magic).
                      This is the build-correct source: it comes from the device or
                      from the device's own firmware, so no offset can be stale.
      * default       the vivo Image at BTF_VA (kept for the earlier round).
    """
    src = BTF_FILE or IMAGE
    with open(src, "rb") as f:
        raw = f.read()
    if BTF_FILE:
        base = raw.find(b"\x9f\xeb\x01\x00")
        if base < 0:
            raise SystemExit("no BTF magic in %s" % src)
    else:
        base = BTF_VA - TEXT_VA
    magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", raw, base)
    if magic != 0xEB9F:
        raise SystemExit("not BTF magic: 0x%x (at 0x%x of %s)" % (magic, base, src))
    end = base + hdr_len + max(type_off + type_len, str_off + str_len)
    blob = raw[base:end]
    types_start = hdr_len + type_off
    strs = blob[hdr_len + str_off: hdr_len + str_off + str_len]

    def s(off):
        if off == 0:
            return ""
        e = strs.find(b"\0", off)
        return strs[off:e].decode("utf-8", "replace")

    types = {}
    pos = types_start
    end = types_start + type_len
    tid = 1
    while pos < end:
        name_off, info, size_type = struct.unpack_from("<III", blob, pos)
        pos += 12
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        kflag = (info >> 31) & 1
        entry = {"id": tid, "kind": kind, "name": s(name_off),
                 "size": size_type, "members": []}
        if kind in (4, 5):
            for _ in range(vlen):
                m_name, m_type, m_off = struct.unpack_from("<III", blob, pos)
                pos += 12
                if kflag:
                    bit_off, bit_sz = m_off & 0xFFFFFF, m_off >> 24
                else:
                    bit_off, bit_sz = m_off, 0
                entry["members"].append((s(m_name), m_type, bit_off, bit_sz))
        elif kind == 1:
            pos += 4
        elif kind == 3:
            pos += 12
        elif kind == 6:
            pos += 8 * vlen
        elif kind == 19:
            pos += 12 * vlen
        elif kind == 13:
            pos += 8 * vlen
        elif kind == 14:
            pos += 4
        elif kind == 15:
            pos += 12 * vlen
        elif kind == 17:
            pos += 4
        types[tid] = entry
        tid += 1
    return types


def main():
    global BTF_FILE
    argv = list(sys.argv)
    if "--btf" in argv:
        i = argv.index("--btf")
        try:
            BTF_FILE = argv[i + 1]
        except IndexError:
            raise SystemExit("--btf 需要跟一个文件路径")
        del argv[i:i + 2]
    sys.argv = argv

    types = load_btf()
    byname = {}
    for t in types.values():
        if t["name"] and t["kind"] in (4, 5):
            byname.setdefault(t["name"], t)

    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd = sys.argv[1]

    if cmd == "list":
        sub = sys.argv[2] if len(sys.argv) > 2 else ""
        hits = sorted(n for n in byname if sub in n)
        for n in hits[:200]:
            print("%-46s size=0x%-5x members=%d"
                  % (n, byname[n]["size"], len(byname[n]["members"])))
        print("(%d of %d)" % (min(len(hits), 200), len(byname)))

    elif cmd == "show":
        name = sys.argv[2]
        t = byname.get(name)
        if not t:
            raise SystemExit("no struct %r (try: list %s)" % (name, name))
        print("struct %s size=0x%x (%d bytes, %d members)"
              % (name, t["size"], t["size"], len(t["members"])))
        for i, (m, mt, bo, bs) in enumerate(t["members"]):
            if not m and i > 0 and i + 1 == len(t["members"]):
                continue  # trailing padding
            extra = " : %d" % bs if bs else ""
            print("  +0x%03x 0x%-3x %-34s %s" % (bo // 8, mt, m, extra))

    elif cmd == "member":
        name, field = sys.argv[2], sys.argv[3]
        t = byname.get(name)
        if not t:
            raise SystemExit("no struct %r" % name)
        for m, mt, bo, bs in t["members"]:
            if m == field:
                print("%s.%s = 0x%x (byte), bit_off=%d, bitsz=%d, type_id=%d"
                      % (name, field, bo // 8, bo, bs, mt))
                return
        raise SystemExit("no member %s in %s" % (field, name))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
