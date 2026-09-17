#!/usr/bin/env python3
"""构建 ghostlock 原生二进制（与 Makefile 等价，但**不需要 make**）。

    python3 tools/build.py              # 编译 ./ghostlock
    python3 tools/build.py --check      # 只打印解析到的编译器与源码清单（不编译）
    python3 tools/build.py --md5        # 编译后与 config/deps.manifest 的基线对照

为什么单独有它：换机后不一定有 GNU make（Windows 上常见），而编译本身只需要 NDK 的 clang。
NDK 探测复用 tools/harness/ghostlock/plat.py，与 harness 用同一套逻辑（含 darwin/windows/linux）。
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "harness"))
from ghostlock import config as glconfig  # noqa: E402
from ghostlock import plat  # noqa: E402

SRCS = ["src/core/main.c", "src/core/offsets_json.c", "src/core/util.c", "src/core/fops.c"]
CFLAGS = ["-O2", "-flto", "-Wall", "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-unused-function"]
LDFLAGS = ["-fPIE", "-pie", "-pthread", "-flto"]


def baseline_md5() -> str:
    mf = REPO / "config" / "deps.manifest"
    if mf.is_file():
        m = re.search(r"^#\s*build-pin:.*ghostlock=([0-9a-f]{32})", mf.read_text(encoding="utf-8"), re.M)
        if m:
            return m.group(1)
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="构建 ghostlock（不需要 make）")
    ap.add_argument("--check", action="store_true", help="只打印解析结果，不编译")
    ap.add_argument("--md5", action="store_true", help="编译后与 build-pin 基线对照")
    ap.add_argument("--api", default="35", help="Android API level（默认 35）")
    ap.add_argument("--target-config", default="target.h", help="目标配置头（默认 target.h）")
    args = ap.parse_args()

    # 载入 L1 本地配置（harness.local.env）并把 ANDROID_* 注入环境，
    # 这样"把 NDK 路径写在 harness.local.env 里"这一种配置方式对构建同样生效。
    cfg = glconfig.build({})
    api = args.api or cfg.get("API") or "35"
    ndk = plat.find_ndk() or cfg.ndk_root()
    if not ndk:
        print("找不到 NDK：请设置 ANDROID_NDK_HOME（或 ANDROID_HOME 指向 SDK 根），"
              f"或写进 {cfg.repo / 'harness.local.env'}", file=sys.stderr)
        return 1
    clang = plat.ndk_clang(ndk, int(api))
    if not clang:
        print(f"NDK 里找不到 aarch64-linux-android{api}-clang：{ndk}", file=sys.stderr)
        return 1

    missing = [s for s in SRCS if not (REPO / s).is_file()]
    if missing:
        print(f"缺少源文件：{missing}", file=sys.stderr)
        return 1

    print(f"  NDK    {ndk}")
    print(f"  CC     {clang}")
    print(f"  SRCS   {' '.join(SRCS)}")
    print(f"  FLAGS  {' '.join(CFLAGS + LDFLAGS)} -DTARGET_CONFIG_H=\"{args.target_config}\"")
    if args.check:
        return 0

    out = REPO / "ghostlock"
    cmd = [plat.as_arg(clang), *CFLAGS, "-Isrc/core", "-Isrc/kernels",
           f'-DTARGET_CONFIG_H="{args.target_config}"', *LDFLAGS,
           *SRCS, "-o", "ghostlock"]
    res = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, errors="replace")
    text = (res.stdout or "") + (res.stderr or "")
    if text.strip():
        print(text.strip())
    if res.returncode != 0:
        print("编译失败", file=sys.stderr)
        return res.returncode
    warns = len(re.findall(r"warning:", text))
    md5 = plat.md5_of(out)
    print(f"  OK     {out}  ({plat.file_size(out)} 字节, md5 {md5})")
    print(f"  警告   {warns} 条")
    if args.md5:
        pin = baseline_md5()
        if not pin:
            print("  （config/deps.manifest 未声明 build-pin 基线）")
        elif md5 == pin:
            print(f"  ✓ 与已验证基线一致（{pin}）")
        else:
            print(f"  ! 与已验证基线不同（基线 {pin}）—— 换过 NDK 版本或源码有改动，需重跑一轮真机复验")
    return 0


if __name__ == "__main__":
    sys.exit(main())
