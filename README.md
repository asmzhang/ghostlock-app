# GhostLock-App

> 中文: [README_ZH.md](README_ZH.md)

## Supported Devices

| Device                       | SoC    | Kernel                                                 |
| ---------------------------- | ------ | ------------------------------------------------------ |
| Xiaomi 15 Pro (haotian)      | SM8750 | `6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`  |
| Redmi K90 (annibale)         | SM8750 | `6.6.77-android15-8-g4a507830d890-ab13636293-4k`       |
| Redmi K90 Ultra (warsaw)     | SM8750 | `6.6.118-android15-8-g608a629fedf7-ab15154340-4k`      |
| OPPO Find N5 (PKH110)        | SM8750 | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k`      |
| OPPO Find X8 (PKB110)        | MT6991 | `6.6.118-android15-8-gebdfad32d749-ab15099304-4k`      |
| Xiaomi 17 Pro Max (popsicle) | SM8850 | `6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k` |

At startup the kernel is matched against the offset tables via `uname -r`; unsupported kernels are rejected immediately. The app shows the kernel support status at the top.

## Quick Start

Open the **GhostLock** app and tap **Run**; the exploit runs automatically.

Install the KernelSU app (`me.weishu.kernelsu`) first so `ksud` is available. Without `ksud`, stages W1/W2 still grant uid 0, but the KernelSU module will not be loaded.

## Command-Line Debugging

The adb/shell environment has no seccomp filter, so the W3 stage is skipped - handy for quick verification:

```powershell
make ghostlock
adb push ghostlock /data/local/tmp/ghostlock
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell /data/local/tmp/ghostlock
```

## Offset Extraction

On Qualcomm devices, `tools/extract_target.py` parses offsets from `boot.img` and `xbl_config.img`. Requires Python 3 and a kallsyms source (`--kallsyms` file or `--kallsyms-finder`). Passing `--llvm-objdump` (or having `llvm-objdump` on PATH/NDK) additionally disassembles the kernel to auto-derive `pselect_waiter_shift` and `off_slide_loggers_0_1`:

```powershell
python tools/extract_target.py `
  boot.img `
  --xbl-config xbl_config.img `
  --format c `
  --out offsets.h
```

### pselect route feasibility

`core_sys_select` copies only 3 x `FDS_BYTES(nfds)` of user fd_set data onto the kernel stack (qwords 0..14 for nfds=320). The futex waiter must land inside that controllable zone: waiter start word + 11 (lock field) <= 14, i.e. the derived shift (waiter offset from the fd_set in qwords) must be <= 3, or task/lock fall into the kernel-zeroed tail and the route cannot work. The script fails with a clear error when the layout is infeasible.

The same kernel version can differ across SoC branches due to PGO/LTO: Xiaomi 15 (`6.6.77`, non-inlined `do_pselect`) puts the waiter at qword 12 (infeasible), while Xiaomi 15 Pro (same `6.6.77`, inlined middle layer) puts it at word 0 and works with `pselect_waiter_shift=-2`.

## Credits & License

Based on the following projects, licensed under Apache License 2.0 (see [LICENSE](LICENSE)):

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
