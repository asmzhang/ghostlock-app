# APatch / KernelPatch 版本要求 — 2026-09-16（源码推导 + 实测锚点）

> 结论先行：**管理器最低 versionCode 11224；其内嵌参考版本 ≤ 内核 .ko 版本即可（不必相等）**。
> .ko 钉死 0.13.8；管理器参考一旦 > 0.13.8 即被内核拒绝，必须连 .ko 一起换。

## 1. 实测锚点（已全流程验证的组合，2026-09-16 终验）

| 组件 | 版本 |
|---|---|
| 管理器 me.bmax.apatch | versionCode **11224**（versionName 9a63e0f，2026-08-06）|
| kernelpatch 模块 | **0.13.8**（`android12-5.10_kernelpatch.ko`，md5 `2b181dee…`）|
| `/data/adb/ap/version` | 11107 |
| su 通道 | `/system/bin/su`（sucompat），版本串 `11107:APatch` |

签名 APK 归档：`_ghostlock_refs/APatch_11224_9a63e0f_HEAD-release-signed.apk`（重装/恢复用这个）。

## 2. 版本机制（源码依据）

- 管理器把内嵌 kpatch 参考版本**随每条 supercall 发给内核**：
  `supercall.h:22 ver_and_cmd = version_code<<32 | 0x1158<<16 | cmd`，
  其中 `version_code = (MAJOR<<16)+(MINOR<<8)+PATCH`（来自 `app/src/main/cpp/version`）。
- 内核侧 kpatch 对 **≤ 自身版本** 的 caller 向后兼容；**caller 参考 > 内核版本才会被拒**
  ⇒ 硬规则：**升级管理器（参考值升高）不得超过 .ko 版本**。
- 握手只验魔数 `SUPERCALL_HELLO_MAGIC = 0x11581158`（scdefs.h:117）——自 0.11.0-dev（vc≈10825）以来从未变过。
- app 源码注释写明要求 kpatch **≥ 0x0a05（0.10.5）**。

## 3. 为什么最低是 11224（三线源码推导）

1. **功能面**：jailbreak/软重启模式于 `a839ba6`（**vc 11222**）引入，但其软重启有 bug；
   `932243d "jailbreak: fix soft reboot"` = **vc 11224** ⇒ 11224 是第一个软重启正确的版本。
2. **ABI 面**：`supercall.h` + `uapi/scdefs.h` 从 a839ba6(11222) 到 `6ec140e`（kp bump 0.13.8）**零差异**
   ⇒ [11222, 11274] 区间管理器与 0.13.8 内核接口一致。
3. **版本方向**：11222–11274 区间管理器内嵌参考为 0.13.2（≤ 0.13.8）⇒ 被内核接受。

## 4. "0.13.2" 的正确理解

0.13.2 是 11222–11274 区间管理器**内嵌的参考值**（兼容窗口的证据），**不是门槛数字**。
源码 HEAD `6ec140e`（vc≈11274）参考已 bump 为 0.13.8——理论兼容（=内核版本），但从未跑过本流程。

## 5. 约束与边界

- 跨 MINOR（0.12 / 0.14）的 ABI 兼容性**未验证**；管理器参考升到 >0.13.8 = 必须连 .ko 一起换。
- **APatch 仓编不出 .ko**：无 kpatch 子树/子模块、CI 无构建步骤；`apd/src/insmod.rs`/`late_load.rs`
  只是运行时加载逻辑。.ko 属 **KernelPatch 项目**按内核预构建
  （refs 有 android12-5.10 / android13-5.10 两枚，均 0.13.8）；本地无 KernelPatch 源码。
- .ko 由 exploit 以用户态 ELF 重定位加载（引用 13 个未导出符号），普通 insmod 装不上——版本与来源都不要换。

## 6. 版本号方案（复算用）

管理器 versionCode = `10200（epoch，version.properties）+ git 提交数`；versionName = git 短哈希。
关键提交：a839ba6=11222（jailbreak 引入）→ 932243d=11224（软重启修复）→ … → 6ec140e=11274（kp 0.13.8）。
tag 11107 与 `/data/adb/ap/version=11107` 对应。
