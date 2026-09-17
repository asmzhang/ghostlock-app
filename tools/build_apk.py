#!/usr/bin/env python3
"""构建 GhostLock APK —— 自动探测并补齐本机构建 App 所需的工具链。

    python3 tools/build_apk.py                # 检查环境并构建 debug APK
    python3 tools/build_apk.py --check        # 只检查环境，不构建
    python3 tools/build_apk.py -- <额外 gradle 参数>

环境变量：
    GHOSTLOCK_NO_INSTALL=1   只检查不自动安装（CI 用）
    GHOSTLOCK_JDK25 / GHOSTLOCK_JDK21   直接指定 JDK 路径（跳过 mise 探测）

为什么需要它：本机构建 App 需要五个条件（JDK25 / JDK21 / GNU 工具链的 cargo / make / SDK+NDK），
任一缺失过去都以难以定位的方式失败。这里能探测的探测、能装的自动装，装不了才报错并给出确切命令。
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "harness"))
from ghostlock import config as glconfig  # noqa: E402
from ghostlock import plat  # noqa: E402

INFO, OK, WARN, ERR, RESET = "\033[36m·\033[0m", "\033[32m✓\033[0m", "\033[33m!\033[0m", "\033[31m✗\033[0m", ""


def info(m: str) -> None:
    print(f"  {INFO} {m}")


def ok(m: str) -> None:
    print(f"  {OK} {m}")


def warn(m: str) -> None:
    print(f"  {WARN} {m}")


def die(m: str) -> None:
    print(f"  {ERR} {m}", file=sys.stderr)
    sys.exit(1)


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd: list[str], timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)


def mise_where(tool: str, spec: str, prefix: str) -> Path | None:
    """在 mise 已安装版本里找满足前缀的；找不到则安装（GHOSTLOCK_NO_INSTALL=1 时只报缺）。"""
    mise = shutil.which("mise")
    if not mise:
        return None
    res = run([mise, "where", f"{tool}@{spec}"])
    cand = res.stdout.strip().splitlines()[0] if res.returncode == 0 and res.stdout.strip() else ""
    if cand and Path(cand).is_dir():
        return Path(cand)
    res = run([mise, "ls", "--installed", tool])
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith(prefix):
            r2 = run([mise, "where", f"{tool}@{parts[1]}"])
            p = r2.stdout.strip()
            if p and Path(p).is_dir():
                return Path(p)
    if os.environ.get("GHOSTLOCK_NO_INSTALL"):
        return None
    info(f"安装 {tool}@{spec} ...")
    run([mise, "install", f"{tool}@{spec}"], timeout=900)
    res = run([mise, "where", f"{tool}@{spec}"])
    p = res.stdout.strip()
    return Path(p) if p and Path(p).is_dir() else None


def main() -> int:
    ap = argparse.ArgumentParser(description="构建 GhostLock APK（自动补齐工具链）")
    ap.add_argument("--check", action="store_true", help="只检查环境，不构建")
    ap.add_argument("gradle_args", nargs="*", help="透传给 gradlew 的额外参数")
    args = ap.parse_args()

    print("\n\033[1m== 环境探测\033[0m")

    # 1. JDK 25 —— Gradle daemon 要求（gradle/gradle-daemon-jvm.properties 的 toolchainVersion）
    jdk25 = os.environ.get("GHOSTLOCK_JDK25") or ""
    if not (jdk25 and Path(jdk25).is_dir()):
        p = mise_where("java", "temurin-25.0.4+7.0.LTS", "temurin-25")
        jdk25 = str(p) if p else ""
    if not jdk25:
        die("找不到 JDK 25。请装一个：mise install java@temurin-25.0.4+7.0.LTS\n     或设置 GHOSTLOCK_JDK25=<路径>")
    ok(f"JDK 25   {jdk25}")
    os.environ["JAVA_HOME"] = jdk25

    # 2. JDK 21 —— buildSrc 用 jvmToolchain(21)，Gradle 不会自动发现 mise 装的 JDK
    jdk21 = os.environ.get("GHOSTLOCK_JDK21") or ""
    if not (jdk21 and Path(jdk21).is_dir()):
        p = mise_where("java", "21.0.2", "21")
        jdk21 = str(p) if p else ""
    if jdk21:
        ok(f"JDK 21   {jdk21}（buildSrc 工具链）")
    else:
        warn("未找到 JDK 21；若 buildSrc 报 languageVersion=21 请 mise install java@21")

    # 3. Rust 必须是 GNU 工具链（本机无 Visual Studio，MSVC linker 不可用）
    cargo = shutil.which("cargo")
    if not cargo:
        die("找不到 cargo（Rust 工具链）")
    vv = run([cargo, "-vV"]).stdout
    if "windows-gnu" not in vv.lower() and os.name == "nt":
        die("cargo 当前不是 GNU 工具链。修正：\n"
            "       mise use -g rust@stable-x86_64-pc-windows-gnu\n"
            "       rustup default stable-x86_64-pc-windows-gnu")
    host_line = next((ln for ln in vv.splitlines() if ln.lower().startswith("host")), "")
    ok(f"cargo    {host_line.strip()}")
    rustup = shutil.which("rustup")
    if rustup:
        installed = run([rustup, "target", "list", "--installed"]).stdout
        if "aarch64-linux-android" not in installed:
            if not os.environ.get("GHOSTLOCK_NO_INSTALL"):
                info("补 Rust target aarch64-linux-android ...")
                run([rustup, "target", "add", "aarch64-linux-android"], timeout=600)
            else:
                warn("缺 Rust target aarch64-linux-android（GHOSTLOCK_NO_INSTALL=1，未自动安装）")

    # 4. SDK / NDK（走共享探测：ANDROID_NDK_HOME / ANDROID_HOME / 常见安装位置）
    cfg = glconfig.build({})
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""
    if not sdk:
        ndk = plat.find_ndk()
        if ndk:
            sdk = str(ndk.parent.parent)          # <sdk>/ndk/<ver> → <sdk>
    if not sdk or not Path(sdk).is_dir():
        die("找不到 Android SDK：请设置 ANDROID_HOME（或 ANDROID_SDK_ROOT）")
    if not (Path(sdk) / "ndk").is_dir():
        die(f"SDK 下没有 ndk/：{sdk}")
    os.environ["ANDROID_HOME"] = sdk
    ok(f"Android  {sdk}")

    # 5. 依赖镜像（到 dl.google.com / repo.maven.apache.org 的 TLS 握手会被中断）
    mirror = Path.home() / ".gradle" / "init.d" / "aliyun-mirror.gradle"
    if mirror.is_file():
        ok("镜像     ~/.gradle/init.d/aliyun-mirror.gradle（全局生效）")
    else:
        warn("未装全局镜像（~/.gradle/init.d/aliyun-mirror.gradle），依赖可能下载失败")
        warn("  可执行： mkdir -p ~/.gradle/init.d && cp gradle/aliyun-mirror.gradle ~/.gradle/init.d/")

    if args.check:
        print("\n环境检查完成（--check，未构建）。")
        return 0

    # ---------------------------------------------------------------- 构建
    print("\n\033[1m== 构建\033[0m")
    gradlew = REPO / ("gradlew.bat" if os.name == "nt" else "gradlew")
    if not gradlew.exists():
        die(f"找不到 gradlew：{gradlew}")
    cmd = [str(gradlew), ":app:assembleDebug", *args.gradle_args, "--no-daemon"]
    if os.environ.get("GHOSTLOCK_USE_CONFIG_CACHE") != "1":
        cmd.append("--no-configuration-cache")
    print("  $ " + " ".join(cmd))
    res = subprocess.run(cmd, cwd=REPO)
    if res.returncode != 0:
        return res.returncode

    apks = sorted((REPO / "app" / "build" / "outputs" / "apk" / "debug").glob("*.apk"),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    if apks:
        print(f"\n\033[1m== 产物\033[0m\n  {apks[0]} ({plat.file_size(apks[0]) / 1024 / 1024:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
