"""命令行入口：python3 tools/harness/harness.py <command> [选项]

主流程：
  run      跑 TUNE/USE 循环（默认）
  root     一键：自检 → 后台监视 → run → 命中即停 → 收尾 → 终验
  deps     依赖自足性检查（换机第一步）
  finish   命中后的收尾（幂等，支持 --dry-run 只读预览）
  stats    汇总轮次日志
  config   打印最终生效配置（等价 --print-config）

离线/探索工具：
  check      仓库与环境自检（py_compile + deps + 产物 md5 对照；--build 顺带编译）
  preflight  .ko 未定义符号 vs 设备 kallsyms 预检
  harvest    命中后取证（把设备证据拉回本地，<tag> 默认 hit）
  stride     mm_struct stride 核对（slabinfo objsize vs offsets.h）
  retry      重启重试循环（默认 8 轮，W1_ATTEMPTS=3）
  scan       shift 扫描（默认 -4 -3 1 2 3 4）
  probe      探测设备 TCP zerocopy 路线（决定走 TCP 还是 pselect）
"""
from __future__ import annotations

import argparse
import os
import re
import sys

from . import config as cfgmod
from . import flow, offline
from .device import Device, detect_device, finish


def print_config(cfg: cfgmod.Config) -> None:
    rows = [
        ("HOST_OS", cfg.get("_HOST_OS")),
        ("REPO", str(cfg.repo)),
        ("WORK_DIR", str(cfg.work_dir)),
        ("DEPS", str(cfg.deps_dir)),
        ("DEV", detect_device(cfg.get("_ADB")) or "<未探测到>"),
        ("TARGET_MODEL", cfg.get("GHOSTLOCK_TARGET_MODEL")),
        ("MODE", cfg.get("MODE")),
        ("ROUNDS", cfg.get("ROUNDS") or "<空>"),
        ("SHIFT", cfg.get("SHIFT") or "<空>"),
        ("CORE/CCORE", f"{cfg.get('CORE') or '<自动探测>'}/{cfg.get('CCORE') or '<自动探测>'}"),
        ("REBOOT_EVERY", cfg.get("REBOOT_EVERY")),
        ("BIN", str(cfg.bin_path)),
        ("KO", str(cfg.ko_path)),
        ("KSUD", str(cfg.ksud_path)),
        ("超时方式", "python 内建（subprocess timeout，无需 coreutils）"),
        ("NDK_ROOT", cfg.get("_NDK_ROOT") or "<未找到>"),
        ("CLANG", cfg.get("_NDK_CLANG") or "<未找到>"),
        ("NDK 已验证版本", _manifest_pin(cfg) or "<未声明>"),
        ("PYTHON", cfg.get("_PYTHON")),
        ("ADB", cfg.get("_ADB")),
        ("LOCAL_ENV", str(cfg.local_env_file) if cfg.local_env_file else "<未使用>"),
        ("TUNED_ENV", str(cfg.tuned_path) if cfg.tuned_path.is_file() else "<未使用>"),
        ("DRY_RUN", "1" if cfg.dry_run else "0"),
        ("exploit 开关",
         f"SKIP_FIXUP={cfg.get('GL_SKIP_FIXUP')} LAYOUT={cfg.get('GL_LAYOUT')} SELF_W2={cfg.get('GL_SELF_W2')} "
         f"INSMOD_ONLY={cfg.get('GL_INSMOD_ONLY')} HOLD={cfg.get('GL_HOLD')} OWNER={cfg.get('GL_OWNER') or '<空>'}"),
        ("APatch 授权表",
         f"pkgs={cfg.get('GL_AP_PKGS')} header={cfg.get('GL_AP_HEADER')} row={cfg.get('GL_AP_ROW_FMT')} force={cfg.get('GL_AP_FORCE')}"),
    ]
    width = max(len(k) for k, _ in rows) + 2
    for k, v in rows:
        print(f"{k:<{width}}{v}")


def _manifest_pin(cfg: cfgmod.Config) -> str:
    try:
        text = cfg.manifest_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"^#\s*build-pin:.*ndk=([^\s]+)", text, re.M)
    return m.group(1) if m else ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="harness.py",
        description="GhostLock harness（Python 跨平台版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("command", nargs="?", default="run",
                   choices=["run", "root", "deps", "finish", "stats", "config",
                            "check", "preflight", "harvest", "stride", "retry", "scan", "probe"])
    p.add_argument("--mode", choices=["tune", "use"], help="tune=探索锁参（默认）；use=读 gl_tuned.env 复跑")
    p.add_argument("--device", help="指定设备序列号（等价 GHOSTLOCK_DEV）")
    p.add_argument("--rounds", help="TUNE/retry 轮数（建议 ≥20）")
    p.add_argument("--shift", help="pselect waiter 字偏移（默认 -2）")
    p.add_argument("--shifts", help="scan：要扫描的 SHIFT 列表，逗号分隔（默认 -4,-3,1,2,3,4）")
    p.add_argument("--build", action="store_true", help="check：顺带编译并检查零警告")
    p.add_argument("--dry-run", action="store_true", help="只打印计划/命令，不碰设备")
    p.add_argument("--print-config", action="store_true", help="打印最终生效配置后退出")
    p.add_argument("--no-finish", action="store_true", help="root：命中后不自动收尾")
    p.add_argument("--skip-preflight", action="store_true", help="root：跳过 deps 自检")
    p.add_argument("args", nargs="*", help="finish=包名 / harvest=tag / stride=期望值")
    args = p.parse_args(argv)

    cli = {}
    if args.mode:
        cli["MODE"] = args.mode
    if args.device:
        cli["GHOSTLOCK_DEV"] = args.device
        os.environ["GHOSTLOCK_DEV"] = args.device
    if args.rounds:
        cli["ROUNDS"] = args.rounds
    if args.shift:
        cli["SHIFT"] = args.shift

    cfg = cfgmod.build(cli, dry_run=args.dry_run, print_config=args.print_config)

    if args.print_config or args.command == "config":
        print_config(cfg)
        return 0

    errs = cfg.validate()
    if errs:
        for e in errs:
            print(f"[config] {e}", file=sys.stderr)
        return 1
    if cfg.get("_NDK_ROOT"):
        pin = _manifest_pin(cfg)
        cur = cfg.ndk_root().name if cfg.ndk_root() else ""
        if pin and cur and cur != pin:
            print(f"[config] 提示：当前 NDK={cur}，已验证构建用的是 {pin} —— 产物哈希会不同；", file=sys.stderr)
            print("[config]       换 NDK 版本后请重跑一轮真机复验（见 config/deps.manifest）。", file=sys.stderr)

    if args.command == "deps":
        return 1 if flow.cmd_deps(cfg) else 0
    if args.command == "run":
        return flow.cmd_run(cfg, force_rounds=int(args.rounds) if args.rounds else None)
    if args.command == "root":
        return flow.cmd_root(cfg, auto_finish=not args.no_finish, skip_preflight=args.skip_preflight)
    if args.command == "stats":
        return flow.cmd_stats(cfg)
    if args.command == "finish":
        serial = detect_device(cfg.get("_ADB"))
        if not serial:
            print("[finish] 未找到 adb 设备", file=sys.stderr)
            return 3
        dev = Device(serial, cfg.get("_ADB"))
        return finish(dev, cfg, dry_run=cfg.dry_run, pkgs=args.args or None)
    if args.command == "check":
        return offline.cmd_check(cfg, do_build=args.build)
    if args.command == "preflight":
        return offline.cmd_preflight(cfg)
    if args.command == "harvest":
        return offline.cmd_harvest(cfg, tag=(args.args[0] if args.args else "hit"))
    if args.command == "stride":
        return offline.cmd_stride(cfg, expect=(args.args[0] if args.args else None))
    if args.command == "retry":
        return offline.cmd_retry(cfg, rounds=int(args.rounds) if args.rounds else 8)
    if args.command == "probe":
        return offline.cmd_probe(cfg)
    if args.command == "scan":
        shifts = None
        if args.shifts:
            shifts = [int(x) for x in args.shifts.split(",") if x.strip()]
        return offline.cmd_scan(cfg, shifts=shifts)
    return 1
