"""Disassemble regions of the vivo 5.15.178 kernel Image (raw arm64).

file_off = VA - 0xffffffc008000000  (Image file offset 0 == _text)
Usage: python disasm_vivo.py <sym> [len]
       python disasm_vivo.py 0xffffffc0082948a4 0x120
"""
import sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

TEXT_VA = 0xFFFFFFC008000000
IMAGE = r"<REFS_DIR>/vivo/Image-5.15.178-android13-8-00005-g14ee4828e57f-ab13224150_A13-era"

def load_syms():
    syms = {}
    pat = re.compile(r"^([0-9a-f]{16})\s+(\S+)$")
    with open(r"<REFS_DIR>/vivo/vivo_syms.txt") as f:
        for line in f:
            m = pat.match(line.strip())
            if m:
                syms[m.group(2)] = int(m.group(1), 16)
    return syms

def disasm(va, length):
    off = va - TEXT_VA
    with open(IMAGE, "rb") as f:
        f.seek(off)
        code = f.read(length)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    out = []
    for ins in md.disasm(code, va):
        out.append("%012x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    return "\n".join(out)

if __name__ == "__main__":
    syms = load_syms()
    arg = sys.argv[1]
    if arg in syms:
        va = syms[arg]
    else:
        va = int(arg, 16)
    length = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x100
    print("; %s = 0x%x (file off 0x%x)" % (arg, va, va - TEXT_VA))
    print(disasm(va, length))
