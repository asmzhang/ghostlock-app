# GhostLock-Oplus

## 支持的设备

| 设备                   | SoC    | 内核版本                                          |
| ---------------------- | ------ | ------------------------------------------------- |
| OPPO Find N5（PHK110） | SM8750 | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k` |
| OPPO Find X8（PKB110） | MT6991 | `6.6.118-android15-8-gebdfad32d749-ab15099304-4k` |

启动时按 `uname -r` 精确匹配 offset 表，未匹配的内核会直接拒绝运行；App 顶部会显示「内核支持 / 不支持」。

## 快速开始

打开 **GhostLock** 应用，点击 **执行** ，软件会自动完成提取流程，
需先自行安装 KernelSU（`me.weishu.kernelsu`）软件以使用 `ksud`，
缺少 `ksud` 时 W1/W2 仍可拿到 uid 0，但不会加载 KernelSU 模块。

## 命令行调试

adb/shell 环境无 seccomp 过滤，会跳过 W3 阶段，适合快速验证：

```powershell
make ghostlock
adb push ghostlock /data/local/tmp/ghostlock
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell /data/local/tmp/ghostlock
```

## 偏移量提取

高通设备可用 `tools/extract_target.py` 从 `boot.img` 和 `xbl_config.img` 解析偏移量，依赖 Python 3 及 kallsyms 来源（`--kallsyms` 文件或 `--kallsyms-finder`）：

```powershell
python tools/extract_target.py `
  boot.img `
  --xbl-config xbl_config.img `
  --format c `
  --out offsets.h
```

## 来源与许可证

基于以下项目改写，继承 Apache License 2.0（见 [LICENSE](LICENSE)）：

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
