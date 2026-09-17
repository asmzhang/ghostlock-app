#!/usr/bin/env python3
"""One-shot verification of a kernel image against what an offsets entry claims.

Motivation: on 2026-09-14 an entire day was lost deriving offsets from a kernel
image that turned out to be a DIFFERENT build than the device's. Every one of
those facts was checkable offline in seconds. This tool is that check, so it
never has to be paid for again.

It answers, from the image alone:
  1. which build is this really?      (localversion + compile time, vs --expect)
  2. do the struct layouts still match? (from the image's embedded BTF)
  3. are the symbol offsets right?     (rebuild kallsyms, print off_* = addr - base)
  4. is the vulnerability still there? (disassemble remove_waiter)

Only step 1 and 2 always work. Step 3 needs `vmlinux-to-elf`, step 4 needs
`llvm-objdump`; both are looked up automatically and skipped with a hint if absent.

Usage:
  kernel_verify.py <kernel-image> --expect 5.15.180-android13-3-32001549 [--base 0xffffffc008000000]
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

# Struct fields the exploit actually depends on. Keep in sync with
# STRUCT_OFFSETS_5_15 / FAKE_WAITER_* / FAKE_TASK_*.
WANTED = {
    "rt_mutex_waiter": ["tree_entry", "pi_tree_entry", "task", "lock",
                        "wake_state", "prio", "deadline", "ww_ctx"],
    "rt_mutex_base": ["wait_lock", "waiters", "owner"],
    "task_struct": ["usage", "prio", "normal_prio", "sched_task_group",
                    "pi_lock", "pi_waiters", "pi_top_task", "pi_blocked_on",
                    "pid", "tgid", "atomic_flags", "real_cred", "cred",
                    "comm", "tasks", "seccomp", "mm"],
    "selinux_state": ["enforcing"],
}

# symbol -> what it feeds in offsets.h
SYMS = ["_text", "init_cred", "init_task", "root_task_group", "selinux_state",
        "selinux_blob_sizes", "security_hook_heads", "nfulnl_logger", "loggers",
        "sysctl_bootid", "remove_waiter"]

FIND = {
    "vmlinux-to-elf": ["vmlinux-to-elf", "vmlinux-to-elf.exe"],
    "objdump": ["llvm-objdump", "llvm-objdump.exe"],
    "nm": ["llvm-nm", "llvm-nm.exe"],
}


def find_tool(key, extra_dirs=()):
    # the running interpreter's Scripts/bin dir first: a venv's console scripts
    # are not on PATH unless it was activated
    here = os.path.dirname(sys.executable)
    for name in FIND[key]:
        for d in (here,) + tuple(extra_dirs):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
        w = shutil.which(name)
        if w:
            return w
    return None


def ndk_bin_candidates():
    """NDK 的 llvm prebuilt bin 目录候选（不写死盘符/版本/prebuilt 名）。
    顺序：ANDROID_NDK_HOME/ANDROID_NDK_ROOT → 各 SDK 根下的 ndk/*（版本号降序）→ 常见安装位置。
    prebuilt 子目录名（windows-x86_64 / darwin-x86_64 / linux-x86_64）一律探测实际存在的。"""
    out = []
    roots = []
    for key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        v = os.environ.get(key)
        if v and os.path.isdir(v):
            roots.append(v)
    sdks = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
            os.environ.get("LOCALAPPDATA") and
            os.path.join(os.environ["LOCALAPPDATA"], "Android", "Sdk"),
            os.path.expanduser("~/Android/Sdk"),
            "/opt/android-sdk", "/usr/local/lib/android/sdk"]
    for sdk in sdks:
        if not sdk:
            continue
        ndkd = os.path.join(sdk, "ndk")
        if not os.path.isdir(ndkd):
            continue
        for v in sorted(os.listdir(ndkd), reverse=True):
            p = os.path.join(ndkd, v)
            if os.path.isdir(p):
                roots.append(p)
    for r in roots:
        pre = os.path.join(r, "toolchains", "llvm", "prebuilt")
        if not os.path.isdir(pre):
            continue
        for name in sorted(os.listdir(pre)):
            b = os.path.join(pre, name, "bin")
            if os.path.isdir(b):
                out.append(b)
    return out


def step1_build(img, expect):
    print("== 1) 这份镜像到底是哪个构建 ==")
    m = re.findall(rb"[0-9]+\.[0-9]+\.[0-9]+-android[0-9]+-[0-9]+-[0-9]+", img)
    vers = list(dict.fromkeys(v.decode() for v in m))[:6]
    for v in vers:
        print("   localversion:", v)
    d = re.findall(rb"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
                   rb" [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]{3} [0-9]{4}", img)
    for v in list(dict.fromkeys(x.decode() for x in d))[:4]:
        print("   编译时间    :", v)
    if expect:
        ok = expect.encode() in img
        print("   ★ 期望 %s -> %s" % (expect, "找到 ✓" if ok else "★未找到★"))
        return ok
    print("   (未给 --expect，跳过比对)")
    return True


def step2_btf(img):
    print("== 2) 结构体布局（镜像内嵌 BTF）==")
    off = img.find(b"\x9f\xeb\x01\x00")
    if off < 0:
        print("   未找到 BTF 魔数 —— 无法离线核对结构体；请用设备 /sys/kernel/btf 或 slabinfo 交叉验证")
        return
    magic, ver, fl, hl, to, tl, so, sl = struct.unpack_from("<HBBIIIII", img, off)
    print("   BTF @0x%x version=%d type_len=%d" % (off, ver, tl))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    with tempfile.NamedTemporaryFile(delete=False, suffix=".btf") as tf:
        tf.write(img)
        tmp = tf.name
    try:
        import btf_dump
        btf_dump.BTF_FILE = tmp
        types = btf_dump.load_btf()
        byname = {}
        for t in types.values():
            if t["name"] and t["kind"] in (4, 5):
                byname.setdefault(t["name"], t)
        for st, fields in WANTED.items():
            t = byname.get(st)
            if not t:
                print("   %-18s -- 未找到 --" % st); continue
            print("   %-18s size=0x%x" % (st, t["size"]))
            mem = {n: bo // 8 for n, mt, bo, bs in t["members"]}
            for f in fields:
                print("      %-16s %s" % (f, ("0x%x" % mem[f]) if f in mem else "-- 缺 --"))
    except Exception as e:
        print("   BTF 解析失败:", e)
    finally:
        os.unlink(tmp)


def step3_syms(img_path, base, outdir):
    print("== 3) 符号偏移（重建 kallsyms）==")
    vt = find_tool("vmlinux-to-elf")
    if not vt:
        print("   缺 vmlinux-to-elf —— 安装：pip install --no-deps vmlinux-to-elf")
        print("   然后补依赖：pip install peewee hexdump colorama click")
        return
    nm = find_tool("nm", ndk_bin_candidates())
    if not nm:
        print("   缺 llvm-nm（NDK 里通常有）")
        return
    elf = os.path.join(outdir, "kernel.verified.elf")
    r = subprocess.run([vt, img_path, elf], capture_output=True, text=True,
                       errors="replace")
    tail = (r.stdout or "") + (r.stderr or "")
    for ln in tail.strip().splitlines()[-4:]:
        print("   ", ln.strip())
    if not os.path.exists(elf):
        print("   重建失败")
        return
    r = subprocess.run([nm, elf], capture_output=True, text=True, errors="replace")
    syms = {}
    for ln in r.stdout.splitlines():
        p = ln.split()
        if len(p) >= 3 and len(p[0]) == 16:
            syms.setdefault(p[2], int(p[0], 16))
    print("   符号数: %d" % len(syms))
    print("   %-26s %-12s %s" % ("symbol", "offset", "-> offsets.h field"))
    field = {"init_cred": "off_init_cred", "init_task": "off_init_task",
             "root_task_group": "off_root_task_group", "selinux_state": "off_selinux_enforcing",
             "selinux_blob_sizes": "off_selinux_blob_sizes",
             "security_hook_heads": "off_security_hook_heads",
             "nfulnl_logger": "off_slide_nfulnl_logger",
             "loggers": "off_slide_loggers_0_1 (+8)",
             "sysctl_bootid": "off_slide_boot_id", "_text": "(base)"}
    for s in SYMS:
        if s in syms:
            a = syms[s] + (8 if s == "loggers" else 0)
            print("   %-26s 0x%07x    %s" % (s, a - base, field.get(s, "")))
        else:
            print("   %-26s -- 未找到 --" % s)
    step4_vuln(elf, syms, outdir)


def step4_vuln(elf_path, syms, outdir):
    print("== 4) 漏洞面（反汇编 remove_waiter）==")
    od = find_tool("objdump", ndk_bin_candidates())
    if not od:
        print("   缺 llvm-objdump，跳过")
        return
    if "remove_waiter" not in syms:
        print("   符号表里没有 remove_waiter，无法定位")
        return
    a = syms["remove_waiter"]
    p = subprocess.run([od, "-d", "--start-address=0x%x" % a,
                        "--stop-address=0x%x" % (a + 0x120), elf_path],
                       capture_output=True, text=True, errors="replace")
    txt = p.stdout
    hits = [ln.strip() for ln in txt.splitlines()
            if re.search(r"\b(str|ldr|mov|add|cbz|b\.)\b", ln)]
    for ln in hits[:26]:
        print("   ", ln)
    print("   [判据] 找 `mrs  xN, SP_EL0` 取 current，再看是否 `str xzr, [xN, #<off>]`")
    print("         off 应等于 BTF 里 task_struct.pi_blocked_on 的字节偏移")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--expect", default=None)
    ap.add_argument("--base", default="0xffffffc008000000")
    a = ap.parse_args()
    img = open(a.image, "rb").read()
    print("镜像 %s  (%.1f MB)" % (a.image, len(img) / 1048576))
    ok = step1_build(img, a.expect)
    step2_btf(img)
    step3_syms(a.image, int(a.base, 0), os.path.dirname(os.path.abspath(a.image)))
    print("== 结论 ==")
    print("  构建号核对:", "通过 ✓" if ok else "★不一致★ —— 不要用这份素材推导偏移")
    sys.exit(0 if ok else 3)


if __name__ == "__main__":
    main()
