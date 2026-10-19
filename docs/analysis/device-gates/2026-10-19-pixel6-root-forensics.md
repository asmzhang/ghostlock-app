# Pixel 6 (oriole) root 取证快照 — 2026-10-19

## 环境
- 设备 22251FDF60004E, boot = apatch_patched_11282_0.13.9_kosa.img (APatch 11107 manager + KP 0.13.9)
- uname: 5.10.157-android13-4-00001-g5c7ff5dc7aac-ab10381520  (注意: 00001/ab10381520 = factory TQ3A.230805.001)
- boot_id (本 boot): 2466a736-63ca-407d-bc54-23db42160370
- getenforce = Enforcing, root context u:r:shell:s0 via su
- pstore 空（本 boot 无崩溃）

## 内核物理布局 (/proc/iomem 铁证)
- Kernel code: PA 0x80000000-0x82c8ffff
- Kernel data: PA 0x82f00000-0x831cffff
- ⇒ kernel_phys_load = 0x8000000**8**? NO = 0x80000000 (2818572288) 确认
- RAM banks: bank0 0x80000000-0xffffffff（分段），bank1 0x880000000-0x9ffffffff

## 内核 VA 基准 (/proc/kallsyms, kptr_restrict=0 后)
- _text = 0xffffffecd5200000
- _stext = _text+0x10000
- _etext = _text+0x19200000? (0xffffffecd6e40000 - _text = 0x19200000)

## 符号 delta 表（_text 相对, extractor 对照）
| 符号 | 真值 delta | extractor | 判定 |
|---|---|---|---|
| init_task | 0x302B0C0 (50507968) | 50507968 | ✓ 精确 |
| init_cred | 0x2FFFB80 (50330496) | 50330456 | ✗ 差 0x28（extractor 低 40B）已修正 |
| root_task_group | 0x3142A40 (51653184) | 51653184 | ✓ 精确 |
| sysctl_bootid | 0x31ABA29 (52083241) | 52083241 | ✓ 精确 |
| empty_zero_page | 0x313E000 (51634176) | 51634176 | ✓ 精确 |
| selinux_state | 0x3195970 (51992944) | —（不存在 selinux_enforcing 符号） | W1 目标改为 selinux_state（写 8 字节零 ⇒ enforcing@+1=0） |
| selinux_enforcing_boot | 0x2EC42E4 | — | boot 参数持有者，非 W1 目标 |

## 线性映射偏移（打偏真凶）
- linear VA(_text) = 0xffffffecd5200000, PA(_text) = 0x80000000
- phys_offset = PAGE_OFFSET + PA - VA = 0xffffff8000000000 + 0x80000000 - 0xffffffecd5200000
- = **0xffffff93aae00000 = 18446724336227291136 (uint64) = -5178538240 (int64)**
- 验证：该 (PAGE_OFFSET, phys_offset) 对预测的 init_cred/init_task/root_task_group/sysctl_bootid 线性 VA 与 kallsyms 全部吻合

## 盲扫 28 轮失败的最终解释
phys_offset 恒错 ⇒ data_alias() 全部偏到无关 RAM ⇒ W1 永远 clean miss（写 8B 垃圾到无害页）⇒ 永不 oops 也永不命中。与 multicast 几何 / waiter 布局 / 竞态无关。

## 待办（root 退出前完成/已留档）
- [x] kallsyms 全量: D:\work\1\_ghostlock_refs\oriole_kallsyms_root.txt (27.7MB)
- [x] iomem: oriole_iomem_root.txt / config: oriole_config_root.txt
- [ ] profile 修复后真机验证 W1（需先解决 Kotlin uint64 编码 → 用负数 -5178538240）
- [ ] KASLR 稳定性: _text 是否跨 boot 恒定（marble 实证恒定；P6 待多 boot 验证——重启后用 boot_id 区分）
