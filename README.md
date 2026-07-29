# GhostLock for OPPO Find N5 / Find X8

支持的设备与内核：

| 设备                   | SoC    | 内核版本                                          |
| ---------------------- | ------ | ------------------------------------------------- |
| OPPO Find N5（PHK110） | SM8750 | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k` |
| OPPO Find X8（PKB110） | MT6991 | `6.6.118-android15-8-gebdfad32d749-ab15099304-4k` |

启动时会先读取 `uname -r`自动选择对应的 offset 表；不受支持的内核会拒绝运行

## 快速开始

```powershell
make ghostlock
.install.ps1
adb shell /data/local/tmp/ghostlock
```

运行前请确保设备上已有 `ksud`。脚本会依次查找：

1. `/data/app/*/me.weishu.kernelsu*/lib/arm64/libksud.so`
2. `/data/local/tmp/ksud`
3. `/data/adb/ksu/bin/ksud`

如果未找到 `ksud`，W1/W2 仍可完成 uid 0 提权，但不会加载 KernelSU

## 偏移量提取

对于高通设备，可以直接使用 `tools/extract_target.py` 从 `boot.img` 和 `xbl_config.img` 解析偏移量

其依赖 Python 3，以及用于提供 kallsyms 的 `--kallsyms` 文件或 `--kallsyms-finder` 工具

```powershell
python tools/extract_target.py `
  boot.img `
  --xbl-config xbl_config.img `
  --format c `
  --out offsets.h
```

## 来源与许可证

本项目参考并基于以下项目：

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)

本项目继承 Apache License 2.0，详见 [LICENSE](LICENSE)
