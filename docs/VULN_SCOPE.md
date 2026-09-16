# 漏洞范围与"可适配边界"

> 结论先行：**漏洞的影响范围极宽（内核 2.6.39 → 7.1，跨 15 年），
> 但"能实际利用"的范围窄得多 —— 它由编译器生成的栈布局决定，必须逐内核验证。**
> 这两件事不能混为一谈，否则会得出错误的适配预期。

---

## 一、漏洞事实（公开数据）

| 项 | 值 |
|---|---|
| CVE | **CVE-2026-43499**（代号 GhostLock） |
| 类型 | **栈上 Use-After-Free** + 竞态（`kernel/locking/rtmutex.c`） |
| 根因 | `remove_waiter()` 用 `current` 而非 `waiter->task` 清除 `pi_blocked_on`；在 proxy-lock 回滚路径（`rt_mutex_start_proxy_lock` 返回 `-EDEADLK`）上清错了对象，导致 waiter 线程的 `pi_blocked_on` 悬垂 |
| 引入 | **Linux 2.6.39-rc1**（2011-05，commit `8161239a8bcc`） |
| 修复 | mainline **7.1-rc1**（commit `3bfdc63936dd`）；stable 分支 6.1.175 / 6.6.140 / 6.12.86 / 6.18.27 / 7.0.4 |
| 前提 | **`CONFIG_FUTEX_PI=y`**（主流内核默认开启） |
| 权限要求 | **无需任何 capability，也无需 user namespace** |
| CVSS | 7.8（High） |

### 受影响内核区间

```
2.6.39 ~ 6.1.175(不含)
6.2    ~ 6.6.140(不含)
6.7    ~ 6.12.86(不含)
6.13   ~ 6.18.27(不含)
6.19   ~ 7.0.4(不含)
```

**换算到 Android**：Android 2.3 时代的内核（2.6.39）到 Android 16 时代的内核都在列。
本项目的目标内核 `5.10.149` 正在区间内，且实测 `CONFIG_FUTEX_PI=y`。

---

## 二、但"受影响" ≠ "可利用"（关键）

公开的失败案例很说明问题：**某 5.10.233 GKI 设备（SM8475）尝试了 17 种栈回收手法，全部失败**。
失败原因不是技术问题，而是：

> `core_sys_select` 的 `stack_fds` 与 `futex_wait_requeue_pi` 的 `rt_mutex_waiter`
> 在该编译器的栈布局下 **架构性地不重叠**。这是编译器（PGO + LTO + BOLT）决定的客观事实。

引用原始仓库的原话：

> "The pselect stack overlay only works when the freed `rt_mutex_waiter` lands
> **within the user-controllable region of the `stack_fds` buffer**."

### 所以真正的"可适配条件"是

| 条件 | 说明 | 能否离线判定 |
|---|---|---|
| ① 内核在受影响区间 | 见上 | ✅ 看 `uname -r` |
| ② `CONFIG_FUTEX_PI=y` | 漏洞前提 | ✅ 看 `/proc/config.gz` |
| ③ **`stack_fds` 与 `rt_mutex_waiter` 栈偏移重叠** | **决定性条件** | ⚠️ 需反汇编/实测 |
| ④ 存在一个能把受控数据写进该栈深度的 syscall | 本项目用 `pselect` | ⚠️ 同上 |
| ⑤ 能绕过 KASLR / CFI / SELinux | Android 特有 | ⚠️ 视内核而定 |

**③ 是唯一真正的门槛**，而它取决于**具体编译产物**，不取决于内核版本号。
同一版本号的两个厂商内核，一个能用一个不能用，完全正常 ——
本项目里 `PSELECT_WAITER_WORD_SHIFT` 在 stock 内核是 `-2`、
在带 KPM 的内核上会变成 `0`，就是这类差异的直接体现。

### 因此适配策略是

```
先按 ① ② 筛出"候选设备"（便宜，看两个文件即可）
   ↓
再看 ③ ④（贵，需要镜像 + 反汇编/实测）
   ↓
最后才是 ⑤（Android 特有加固）
```

**已适配 ≠ 只有这些能用；未适配 ≠ 一定不能用。** 必须逐个内核验证。

---

## 三、这对 app 的 minSdk 意味着什么

要区分两个不同的"范围"：

| | 范围 | 决定因素 |
|---|---|---|
| **漏洞影响范围** | Android 2.3 ~ 16+ | 内核版本（很宽） |
| **本项目实际可适配范围** | 目前 5.10 / 6.1 / 6.6 / 6.12（Android 12 ~ 16） | 逐个内核验证过（窄） |

**app 的角色是"工具"**：导入镜像 → 提取偏移 → 生成补丁 → 显示状态。
它**本身不跑漏洞**，所以它的 minSdk 应该按**用户可能拿它做什么**来定，
而不是按"已适配内核列表"来定 —— 因为用户可能正想用它去适配一台老设备。

**决策**：minSdk 取依赖允许的下限（**21 / Android 5.0**），并在 UI 上对
"不在已知适配列表内的内核"给出**明确提示**（而不是直接拒绝），
让用户知道可以去尝试提取与验证。

> 原先上游设 `minSdk = 34`（面向 Pixel 6 / Android 14），会把 Android 12/13 的
> 设备直接挡在门外 —— 而漏洞在这些版本上恰恰是受影响的。

---

## 四、没有 boot 镜像怎么办

提取偏移需要"能看到内核内部结构"的素材。按可用性排序，**boot 镜像只是其中一种**：

### 方案 A · 设备已 root（最省事）

```bash
adb shell 'su -c "cat /proc/kallsyms"'            > work/kallsyms_<model>.txt
adb shell 'su -c "cat /proc/config.gz" | gunzip'  > work/config_<model>.txt
```

有了 kallsyms 就能解析出**符号地址**；结构体内偏移再结合反汇编或 BTF 推导。
`--kallsyms` 参数就是为这条路准备的。

> 注意：未 root 时 `/proc/kallsyms` 的地址会被 `kptr_restrict` 清零，
> 而**适配恰恰发生在提权之前** —— 所以这条路需要设备已有其他 root 途径。

### 方案 B · 设备自带 BTF（无需镜像，但并非所有内核都带）

```bash
adb shell 'ls -la /sys/kernel/btf/vmlinux'
```

存在则可直接读结构体布局，**完全不需要 boot 镜像**。
Android GKI 内核常带，但**本项目的目标设备没有**（实测
`/sys/kernel/btf/vmlinux: No such file or directory`）—— 属 BTF-less 内核，
需要走方案 A/C/D。

### 方案 C · 从 OTA / 工厂包提取（无需设备）

```bash
./ghostlock-extract payload.bin --format json --out offsets.json
./ghostlock-extract https://<ota-host>/payload.bin --out offsets.json
```

工具直接支持 **payload.bin / OTA ZIP / http(s) OTA 地址** —— 只要能拿到官方包即可。

### 方案 D · 直接从设备 dd 出分区（需要 root 或可读块设备）

```bash
adb shell 'su -c "ls -la /dev/block/by-name/"'        # 先看分区表
adb shell 'su -c "dd if=/dev/block/by-name/boot of=/data/local/tmp/boot.img"'
adb pull /data/local/tmp/boot.img work/
```

**Android 13+ 注意**：内核可能不在 `boot` 分区，而在 **`init_boot`** 或 **`vendor_boot`**；
GKI 设备上 `boot` 里通常只有通用内核 + 厂商 `vendor_boot` 里的 DTBO/模块。
**几个分区都要试**。

### 方案 E · 从内核源码 + 配置重建

拿到 `/proc/config.gz`（本设备可读）与对应版本源码，本地编译出同配置的 `Image`，
再用工具提取。成本最高，但在没有任何镜像来源时可行。

### 附加：XBL 物理加载地址

部分机型需要额外 `xbl_config.img` 才能推导内核物理加载地址：

```bash
./ghostlock-extract boot.img --xbl-config xbl_config.img --register
# 或直接指定
./ghostlock-extract boot.img --phys 0xc7800000
```

---

## 五、判断一台设备"值不值得试"的快速清单

```bash
adb shell 'uname -r'                                    # ① 在受影响区间吗
adb shell 'zcat /proc/config.gz | grep CONFIG_FUTEX_PI' # ② 前提满足吗
adb shell 'ls /sys/kernel/btf/vmlinux'                  # 有 BTF 吗（决定提取难度）
adb shell 'ls /dev/block/by-name/ | grep -E "boot|init_boot|vendor_boot"'  # 镜像从哪来
```

前两条通过 → 进入偏移提取与栈布局验证（③ ④）。
**③ 不过就放弃，不是技巧问题，是编译器布局问题。**
