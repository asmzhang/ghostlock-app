#!/usr/bin/env python3
"""check_readme_devices.py — 校验 README 设备表与 src/kernels/ 是否同步。

背景（2026-09-15 发现）：README 的"支持的设备"表 = App 精确匹配 `uname -r` 的偏移表清单
（README 原文："未匹配的内核直接拒绝运行"）。但"加 src/kernels/<ver>/offsets.h"与"更新 README 表"
是两件独立的事，历史上漏同步过（5.10.149 / 5.15.178 / 5.15.180 三个条目都只加了代码）。

用法：
    python tools/check_readme_devices.py            # 报告差异
    python tools/check_readme_devices.py -v         # 连表里每一行都打出来

退出码：0 = 完全一致；1 = 有差异（可直接用于 CI/提交前检查）。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|")


def readme_devices(path: Path):
    out = []
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = ROW.match(line)
        if m:
            out.append(m.group(1))
    return out


def kernel_dirs():
    d = ROOT / "src" / "kernels"
    return sorted(p.name for p in d.iterdir() if p.is_dir())


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    code = kernel_dirs()
    rc = 0
    for name in ("README_ZH.md", "README.md"):
        rows = readme_devices(ROOT / name)
        print(f"===== {name} =====")
        if rows is None:
            print("  (文件不存在)")
            continue
        print(f"  表里 {len(rows)} 行 / 代码里 {len(code)} 个内核条目")
        only_table = [r for r in rows if r not in code]
        only_code = [r for r in code if r not in rows]
        if only_table:
            rc = 1
            print(f"  ❌ 表里有、代码里没有（{len(only_table)}）：")
            for r in only_table:
                print(f"     {r}")
        if only_code:
            # 注意：新增条目是否"可用"是另一件事；这里只报"没写进表"
            print(f"  ⚠  代码里有、表里没有（{len(only_code)}）—— 需确认状态后决定是否补表：")
            for r in only_code:
                print(f"     {r}")
        if not only_table and not only_code:
            print("  ✅ 一致")
        if verbose:
            for r in rows:
                print(f"     - {r}")
    if rc == 0:
        print("\n(代码有/表没有 不计为错误：可能是故意不列入的支持状态。)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
