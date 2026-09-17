"""流程编排：deps 自检 / run（tune|use）/ root（一键）/ stats。

这一层只做"顺序与判定"，具体动作在 device.py。
"""
from __future__ import annotations

import re
import time
from pathlib import Path

from . import plat
from .config import Config, load_tuned
from .device import Device, Watcher, bad, detect_core_pair, detect_device, finish, ok, stage, warn

HIT_RE = re.compile(r"child is root!|self is root")


def parse_manifest(path: Path) -> list[tuple[str, str, str, str]]:
    """解析 config/deps.manifest：<文件名> <字节> <md5> <说明>；# 开头为注释。"""
    rows = []
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 3)
            if len(parts) >= 3:
                rows.append((parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else ""))
    except OSError:
        pass
    return rows


def cmd_deps(cfg: Config) -> int:
    fails = 0
    print("\n== 目录")
    print(f"  REPO      {cfg.repo}")
    print(f"  WORK_DIR  {cfg.work_dir}")
    print(f"  DEPS      {cfg.deps_dir}")
    print(f"  LOGDIR    {cfg.log_dir}")

    print(f"\n== 依赖清单（{cfg.manifest_path}）")
    rows = parse_manifest(cfg.manifest_path)
    if not rows:
        warn("清单不存在或为空，跳过逐项校验")
    for name, size, md5, note in rows:
        p = cfg.deps_dir / name
        if not p.is_file():
            bad(f"缺 {name} —— 期望在 {cfg.deps_dir}/（{note}）")
            print(f"       修复：把 {name} 放到 {cfg.deps_dir}，或设置 GHOSTLOCK_DEPS=<所在目录>")
            fails += 1
            continue
        got_size, got_md5 = plat.file_size(p), plat.md5_of(p)
        if str(got_size) != size or got_md5 != md5:
            bad(f"{name} 与清单不一致（size {got_size}/{size}，md5 {got_md5}/{md5}）")
            warn(f"       若换了 .ko 版本，请同步更新 {cfg.manifest_path} 并重跑一轮真机复验")
            fails += 1
        else:
            ok(f"{name}  ({size} 字节, md5 匹配)")

    print("\n== 构建产物")
    if cfg.bin_path.is_file():
        ok(f"{cfg.bin_path.name}  ({plat.file_size(cfg.bin_path)} 字节, md5 {plat.md5_of(cfg.bin_path)})")
        print("       提示：已验证构建 md5 见 config/deps.manifest（NDK 版本不同则产物不同）")
    else:
        warn(f"还没有 {cfg.bin_path} —— 构建：make ghostlock（需 NDK）")

    print("\n== 工具链")
    ndk = cfg.ndk_root()
    if ndk:
        ok(f"NDK  {ndk}")
        clang = cfg.get("_NDK_CLANG")
        (ok if clang else bad)(f"clang {clang}" if clang else f"NDK 里找不到 aarch64-linux-android{cfg.get('API')}-clang")
        fails += 0 if clang else 1
    else:
        bad("找不到 NDK —— 设 ANDROID_NDK_HOME（或 ANDROID_HOME 指向 SDK 根）")
        fails += 1
    adb = cfg.get("_ADB")
    if plat.which(adb) or Path(adb).exists():
        ok(f"adb  {adb}")
    else:
        bad(f"PATH 里没有 adb（或设 GHOSTLOCK_ADB=<adb 路径>），当前={adb}")
        fails += 1
    ok(f"python {cfg.get('_PYTHON')}  ({plat.host_os()})")

    print("\n== 结果")
    if fails == 0:
        print("  全部就绪。下一步：python3 tools/harness/harness.py root --dry-run 看一眼计划，再去掉 --dry-run 实跑。")
    else:
        print(f"  {fails} 项未通过，请按上面的提示处理后再跑。")
    return fails


def _round_log(cfg: Config, r: int) -> Path:
    return cfg.log_dir / f"gl_tune_r{r}.log"


def cmd_run(cfg: Config, force_rounds: int | None = None) -> int:
    """TUNE / USE 主循环。返回 0=命中，2=轮数用尽未命中，3=前置失败。"""
    dev_serial = detect_device(cfg.get("_ADB"))
    if not dev_serial:
        bad("未找到 adb 设备。请连接设备，或设置 GHOSTLOCK_DEV=<序列号>（多设备时必须指定）。")
        return 3
    dev = Device(dev_serial, cfg.get("_ADB"))
    rounds = force_rounds or cfg.get_int("ROUNDS") or 10

    tuned: dict[str, str] = {}
    if cfg.get("MODE") == "use":
        try:
            tuned = load_tuned(cfg)
        except FileNotFoundError:
            bad(f"MODE=use 需要 {cfg.tuned_path}（TUNE 命中时会生成），当前不存在。")
            print("       先跑一次 TUNE：python3 tools/harness/harness.py run")
            return 3
    core, ccore = cfg.get("CORE").strip(), cfg.get("CCORE").strip()
    if not core or not ccore:
        core = core or tuned.get("CORE") or ""
        ccore = ccore or tuned.get("CCORE") or ""
        if not core or not ccore:
            core, ccore = detect_core_pair(dev)
    shift = cfg.get("SHIFT") or tuned.get("SHIFT") or "-2"
    cfg.values["SHIFT"] = shift
    cfg.values["CORE"], cfg.values["CCORE"] = str(core), str(ccore)

    envstr = cfg.exploit_env(core, ccore)
    print(f"=== MODE={cfg.get('MODE')} rounds={rounds} shift={shift} core={core}/{ccore} {time.strftime('%H:%M:%S')} ===")
    if cfg.local_env_file:
        print(f"--- 本地配置: {cfg.local_env_file}")
    if tuned:
        print(f"--- 锁定参数: {cfg.tuned_path}")
    print(f"--- 设备命令: cd {cfg.d_tmp} && {envstr} ./ghostlock")

    if cfg.dry_run:
        print("--- DRY-RUN：以下为将要推送/执行的命令，未实际执行 ---")
        print(f"push {plat.as_arg(cfg.bin_path)} -> {cfg.d_tmp}/ghostlock")
        print(f"push {plat.as_arg(cfg.ko_path)} -> {cfg.d_tmp}/kernelpatch.ko")
        print(f"push {plat.as_arg(cfg.ko_path)} -> {cfg.d_sdcard}/ghostlock_ko/kernelpatch.ko")
        print(f"push {plat.as_arg(cfg.ksun_path)} -> {cfg.d_sdcard}/ghostlock_ko/kernelsu.ko")
        print(f"push {plat.as_arg(cfg.ksud_path)} -> {cfg.d_sdcard}/ghostlock_ko/ksud")
        print(f'adb -s {dev.serial} shell "cd {cfg.d_tmp} && {envstr} ./ghostlock"   (超时 400s, 共 {rounds} 轮)')
        return 0

    panic = safe = hit = 0
    reboot_every = cfg.get_int("REBOOT_EVERY") or 0
    for r in range(1, rounds + 1):
        # 新鲜态维护：实测 W1 存活率从刚开机 ~25% 掉到长期 panic 后 ~7%，按需定期重启。
        if reboot_every > 0 and r > 1 and (r - 1) % reboot_every == 0:
            print(f"--- periodic reboot (round {r}) to restore fresh state ---")
            dev.adb("reboot", timeout=30)
            time.sleep(50)
        u0 = dev.shell("cat /proc/uptime").split(" ")[0] if dev.shell("cat /proc/uptime") else "?"
        print(f"=== TUNE round {r}/{rounds} shift={shift} core={core}/{ccore} uptime={u0} {time.strftime('%H:%M:%S')} ===")
        if not stage(dev, cfg):
            print("stage failed; waiting for next boot")
            time.sleep(20)
            continue
        res = dev.adb("shell", f"cd {cfg.d_tmp} && {envstr} ./ghostlock", timeout=400)
        log = _round_log(cfg, r)
        log.write_text((res.stdout or "") + (res.stderr or "") + f"\nADB_EXIT={res.returncode}\n", encoding="utf-8")
        text = log.read_text(encoding="utf-8", errors="replace")
        u_after = dev.shell("cat /proc/uptime")

        if HIT_RE.search(text):
            hit += 1
            if cfg.get("MODE") == "tune":
                cfg.tuned_path.write_text(
                    f"SHIFT={shift} CORE={core} CCORE={ccore} DATE={time.strftime('%Y-%m-%d %H:%M:%S')}\n",
                    encoding="utf-8",
                )
                print(f"=== SUCCESS (hit {hit}) — params locked to {cfg.tuned_path}; verifying module + APatch ===")
            else:
                print(f"=== SUCCESS (hit {hit}) — USE 模式（{cfg.tuned_path} 未改动）；verifying module + APatch ===")
            time.sleep(8)
            print("--- /proc/modules ---")
            print(dev.shell("grep -E 'kernelsu|kernelpatch' /proc/modules 2>/dev/null || echo '(none)'"))
            print("--- klog ---")
            print(dev.shell(f"cat {cfg.d_sdcard}/ghostlock_klog 2>/dev/null || cat {cfg.d_tmp}/.ghostlock_klog 2>/dev/null || echo '(no klog)'"))
            print("--- su -c id ---")
            print(dev.shell("su -c id 2>&1 | head -3", timeout=25))
            print("--- root worker marker ---")
            print(dev.shell(f"ls -la {cfg.d_tmp}/.ghostlock_root_alive 2>/dev/null || echo '(none)'"))
            break
        if not u_after:
            panic += 1
            print(f"result: PANIC (fired, died) — cumulative panic={panic} safe={safe} hit={hit}")
        else:
            safe += 1
            print(f"result: SAFE-NO-FIRE (survived, no write) — panic={panic} safe={safe} hit={hit}")
        time.sleep(2)

    print(f"=== TUNE done: hit={hit} panic={panic} safe={safe} over {rounds} rounds {time.strftime('%H:%M:%S')} ===")
    return 0 if hit else 2


def cmd_root(cfg: Config, auto_finish: bool = True, skip_preflight: bool = False) -> int:
    """一键：自检 → 后台监视 → run → 命中即停 → 收尾 → 终验。
    退出码 0=已 root / 2=轮数用尽未命中 / 3=前置失败 / 4=命中但收尾或终验失败。"""
    stamp = time.strftime("%Y%m%d_%H%M%S")
    run_log = cfg.log_dir / f"root_{stamp}.log"
    if cfg.dry_run:
        print(f"MODE={cfg.get('MODE')} ROUNDS={cfg.get('ROUNDS')} SHIFT={cfg.get('SHIFT')} 设备={detect_device(cfg.get('_ADB')) or '<未探测到>'}")
        print(f"WORK_DIR={cfg.work_dir}\nBIN={cfg.bin_path}\n日志={run_log}")
        print("\n--- DRY-RUN：计划（未执行）---")
        print("  ① deps 自检" + ("（已跳过）" if skip_preflight else ""))
        print(f"  ② 后台监视 /proc/modules → {cfg.log_dir / '_watcher.log'}")
        print(f"  ③ TUNE 循环 {cfg.get('ROUNDS')} 轮 → {run_log}")
        print("  ④ 命中后在轮次日志中匹配 'is root'")
        print("  ⑤ finish 收尾" if auto_finish else "  ⑤ 跳过收尾（--no-finish）")
        print("  ⑥ 终验 su -c id（期望 uid=0 gid=0 context=u:r:magisk:s0）")
        return 0

    print("\n== 2/6 前置检查")
    dev_serial = detect_device(cfg.get("_ADB"))
    if not dev_serial:
        bad("未找到 adb 设备")
        return 3
    dev = Device(dev_serial, cfg.get("_ADB"))
    if skip_preflight:
        print("  已跳过依赖自检（--skip-preflight）")
    elif cmd_deps(cfg) != 0:
        bad("依赖自检未通过")
        return 3

    print("\n== 3/6 启动监视（独立盯 /proc/modules）")
    watcher = Watcher(dev, cfg)
    watcher.start()
    print(f"  watcher → {watcher.log_path}")

    print("\n== 4/6 跑循环（命中即自动停止；单轮命中率约 5–8%）")
    rc = cmd_run(cfg)
    watcher.stop()

    if rc != 0:
        print("\n== 5/6 轮数用尽，未命中")
        print("  这不是失败——是概率事件：加大轮数重跑（--rounds 50），或先确认设备处于新鲜态。")
        return 2

    print(f"\n== 5/6 命中（watcher 记录：{'已检出' if watcher.detected else '见日志'}）")
    if auto_finish:
        print("  执行收尾 finish（幂等：无模块时安全退出）")
        frc = finish(dev, cfg)
        if frc not in (0,):
            bad(f"finish 返回 {frc}，请查看上面输出")
            return 4
    else:
        print("  已跳过收尾；可手动执行：python3 tools/harness/harness.py finish")

    print("\n== 6/6 终验")
    idl = dev.id_line()
    print(f"  {idl}")
    if dev.has_root():
        ok("root 就绪（uid=0 + u:r:magisk:s0）")
        print("\n  提醒：这是 exploit 形态的 root —— 真机重启会丢，需要时重跑本命令。")
        return 0
    bad("终验未达标（期望 uid=0 与 u:r:magisk:s0）")
    print(f"  排查：{run_log} 与 {cfg.log_dir / '_watcher.log'}；收尾是幂等的，可再跑 finish。")
    return 4


def cmd_stats(cfg: Config) -> int:
    logdir = cfg.log_dir
    print(f"日志目录：{logdir}")
    print(f"{'log':<26}{'rounds':>7}{'hit':>6}{'panic':>7}{'safe':>6}")
    tot = [0, 0, 0, 0]
    files = sorted(list(logdir.glob("gl_run*.out")) + list(logdir.glob("harness_run_*.out")) + list(logdir.glob("root_*.log")))
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        rounds = len(re.findall(r"^=== TUNE round", text, re.M))
        if not rounds:
            continue
        hit = len(re.findall(r"is root|=== SUCCESS", text))
        panic = len(re.findall(r"result: PANIC", text))
        safe = len(re.findall(r"result: SAFE", text))
        print(f"{f.name:<26}{rounds:>7}{hit:>6}{panic:>7}{safe:>6}")
        for i, v in enumerate((rounds, hit, panic, safe)):
            tot[i] += v
    print("-" * 52)
    print(f"{'TOTAL':<26}{tot[0]:>7}{tot[1]:>6}{tot[2]:>7}{tot[3]:>6}")
    return 0
