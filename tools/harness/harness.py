#!/usr/bin/env python3
"""GhostLock harness 入口（Python 跨平台版）。

    python3 tools/harness/harness.py root --rounds 30     # 一键：自检→监视→循环→命中即停→收尾→终验
    python3 tools/harness/harness.py deps                 # 换机第一步：依赖自足性检查
    python3 tools/harness/harness.py run --dry-run        # 只打印将执行的设备命令
    python3 tools/harness/harness.py config               # 打印最终生效配置

为什么不是 shell：shell 版依赖 coreutils（timeout / md5sum / stat）与 MSYS 路径行为，
Windows(Git Bash) / Linux / macOS 表现不一致；Python 只有一个运行时依赖，
路径、哈希、超时、进程管理都是标准库行为（见 tools/harness/ghostlock/）。
"""
import sys
from pathlib import Path

# 输出改为行缓冲：脚本常被重定向到日志文件（> gl_run.out），
# 默认块缓冲会让日志在长时间运行期间一直为空（实测踩过一次）。
try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:  # pragma: no cover - 老解释器没有 reconfigure
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghostlock.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
