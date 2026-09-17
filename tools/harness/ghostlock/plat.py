"""平台/工具链适配 —— 只在这里出现"平台差异"。

覆盖：md5、超时执行、文件大小、NDK 探测、adb 定位。
业务代码不再关心 windows / darwin / linux。
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = os.name == "nt"


def host_os() -> str:
    if IS_WINDOWS:
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def md5_of(path: Path | str, chunk: int = 1 << 20) -> str:
    """文件 md5（小写十六进制）。用标准库，替代 md5sum/md5 -q。"""
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def file_size(path: Path | str) -> int:
    return os.path.getsize(path)


def which(name: str) -> str | None:
    """定位可执行文件；Windows 上补 .exe/.cmd/.bat 后缀。"""
    hit = shutil.which(name)
    if hit:
        return hit
    if IS_WINDOWS:
        for ext in (".exe", ".cmd", ".bat"):
            hit = shutil.which(name + ext)
            if hit:
                return hit
    return None


def as_arg(path: Path | str) -> str:
    """传给外部程序的路径：统一正斜杠。
    adb.exe 只认 Windows 盘符路径（D:/...），反斜杠与 POSIX /d/... 都会静默失败。"""
    return str(path).replace("\\", "/")


def run(cmd: list[str], timeout: float | None = None, capture: bool = True) -> subprocess.CompletedProcess:
    """统一执行：超时用 subprocess 自身实现，不需要 coreutils 的 timeout。"""
    return subprocess.run(
        cmd,
        timeout=timeout,
        capture_output=capture,
        text=True,
        errors="replace",
    )


def adb_binary() -> str:
    """adb 定位顺序：GHOSTLOCK_ADB / ADB → PATH。"""
    for key in ("GHOSTLOCK_ADB", "ADB"):
        v = os.environ.get(key)
        if v:
            return v
    hit = which("adb")
    return hit or "adb"


# ---------------------------------------------------------------- Android NDK
def _newest_dir(paths: list[Path]) -> Path | None:
    cands = [p for p in paths if p.is_dir()]
    if not cands:
        return None
    return sorted(cands, key=lambda p: p.name)[-1]


def find_ndk() -> Path | None:
    """NDK 根目录探测（不含任何写死本机路径）：
    ANDROID_NDK_HOME / ANDROID_NDK_ROOT → 各 SDK 根的 ndk/*（版本最高）→ 常见安装位置。"""
    for key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        v = os.environ.get(key)
        if v and Path(v).is_dir():
            return Path(v)
    sdk_roots = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk") if os.environ.get("LOCALAPPDATA") else None,
        str(Path.home() / "Android" / "Sdk"),
        "/opt/android-sdk",
        "/usr/local/lib/android/sdk",
    ]
    for sdk in sdk_roots:
        if not sdk:
            continue
        ndk_dir = Path(sdk) / "ndk"
        if ndk_dir.is_dir():
            got = _newest_dir(list(ndk_dir.iterdir()))
            if got:
                return got
    return None


def ndk_prebuilt_bin(ndk: Path | None) -> Path | None:
    """toolchains/llvm/prebuilt/*/bin —— prebuilt 目录名随宿主/版本变化，探测实际存在的。"""
    if not ndk:
        return None
    pre = Path(ndk) / "toolchains" / "llvm" / "prebuilt"
    if not pre.is_dir():
        return None
    for d in sorted(pre.iterdir()):
        if (d / "bin").is_dir():
            return d / "bin"
    return None


def ndk_clang(ndk: Path | None, api: int = 35) -> Path | None:
    bindir = ndk_prebuilt_bin(ndk)
    if not bindir:
        return None
    base = f"aarch64-linux-android{api}-clang"
    for name in (base + ".cmd", base) if IS_WINDOWS else (base,):
        p = bindir / name
        if p.exists():
            return p
    return None
