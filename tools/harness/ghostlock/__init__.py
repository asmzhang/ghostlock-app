"""GhostLock harness —— Python 跨平台实现。

为什么是 Python：原来的 bash 版依赖 coreutils（timeout/md5sum/stat）与 MSYS 路径行为，
在 Windows(Git Bash)/Linux/macOS 之间表现不一致；Python 只有一个运行时依赖（python3），
路径/哈希/超时/进程管理都是标准库行为，换机换平台不需要改脚本。

模块边界：
  config.py  四层配置（L0 CLI/env > L1 harness.local.env > L3 默认+探测）+ 路径解析
  plat.py    平台/工具链：md5、超时、NDK 探测、adb 定位
  device.py  adb 设备操作：探测、推送校验、收尾流程、/proc/modules 监视
  flow.py    流程编排：deps / run(tune|use) / root 一键 / stats
  cli.py     命令行入口
"""

__version__ = "1.0.0"
