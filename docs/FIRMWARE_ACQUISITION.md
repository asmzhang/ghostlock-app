# 获取固件 / 内核源码的通用方法

> 适配一台**未 root 且厂商封锁严密**的设备时，第一步就卡在"拿不到内核符号"。
> 本文记录一条**通用且合法**的路径，以及 2026-09-11 在 vivo V27 上的完整实战。

## 0. 核心洞察

**厂商可以锁 bootloader、可以把 `/proc/kallsyms` 读权限关掉、可以封掉块设备 ——
但 GPL 逼它们必须公开内核源码。**

```c
/* 只要内核里含 GPL 代码（Linux 内核必然含），厂商就负有源码公开义务 */
```

所以：**官方开源站是每个厂商都必须提供的入口**，而且通常**不需要登录、不限速**。
这条路比"找 OTA 整包"、"等有人把镜像传上网盘"可靠得多。

## 0.5 ★ 首选路径：GKI 设备直接用 Google 官方 CDN

**如果目标设备是 GKI 内核（Android 11+ 且 `uname -r` 形如
`X.Y.Z-androidN-NN-g<commit>-ab<buildid>`），先试这条 —— 它是所有路径里
最快、最准、最省事的，实测 21MB、几十秒、版本精确匹配。**

### 原理：`uname -r` 里藏着 AOSP 的提交 hash

```
5.15.178-android13-8-00007-g362d545d31a5-ab14608873
^^^^^^^^  ^^^^^^^^^  ^^^^^  ^^^^^^^^^^^^  ^^^^^^^^^^
上游版本   AOSP 分支  序号    AOSP 提交     build id
```

**`android13-8` 是 AOSP 的分支命名格式**，拿 `g` 后面那串去
`android.googlesource.com/kernel/common` 就能反查出确切提交：

```bash
curl -s "https://android.googlesource.com/kernel/common/+/362d545d31a5?format=JSON"
```

实战输出（vivo V27）：

```json
{
  "commit": "362d545d31a5659546d5546c7ae206f745e98c3e",
  "author": { "email": "yangshiyou@vivo.corp-partner.google.com" },
  "committer": { "time": "Wed Dec 17 08:29:33 2025 -0800" },
  "message": "ANDROID: GKI: Update symbol list for vivo\n..."
}
```

**与设备 `/proc/version` 的 `Wed Dec 17 16:29:33 UTC 2025` 逐秒吻合** ——
确认这就是设备在跑的那个提交。

**这一步的价值不只是"确认"**：如果提交的 message 是
`ANDROID: GKI: Update symbol list for <厂商>`（**只加符号、不改代码**），
就说明**厂商内核 = AOSP GKI + 少量符号提交**，
于是 **Google 官方 build 的符号表与设备高度一致**，可以直接拿来用。

### 版本号 → 分支 的对照

AOSP 按月发布，分支名形如 `android13-5.15-YYYY-MM`：

```
5.15.178-android13  →  2025-03  →  android13-5.15-2025-03
5.15.194-android13  →  2025-12  →  android13-5.15-2025-12
```

完整对照表见 AOSP 文档 *GKI release builds*；也可用
`git ls-remote --heads https://android.googlesource.com/kernel/common` 列出全部分支。

### 下载（★ 真正的入口）

```bash
# certified 版（普通 boot.img）
https://dl.google.com/android/gki/gki-certified-boot-android13-5.15-<分支>_r<N>.zip

# debug 版（含 ALLSYMS，符号最全）
https://dl.google.com/android/gki/gki-debug-boot-android13-5.15-<分支>_r<N>.zip

# 某个 build 的全部 artifact（含 vmlinux / System.map）
https://ci.android.com/builds/submitted/<build_id>/kernel_aarch64/latest
```

**实测**（2025-03 分支，r1/r2/r3 全部存在，每个约 **21 MB**）：

```
android13-5.15-2025-03_r1       21,547,639  ✅
android13-5.15-2025-03_r1-gz    21,448,373  ✅
android13-5.15-2025-03_r1-lz4   21,922,097  ✅
```

> 注意：`dl.google.com/android/gki/` 不需要登录；而
> `source.android.com` 的文档页需要 Google 登录（浏览器自动化也带不了登录态），
> **别在那里绕** —— 认准 `dl.google.com` 这个 CDN 即可。

### ⚠️ 提取内核时的坑：GKI 的 boot.img 是 **header v4**

**v4 与 v0 的字段布局不同**，按 v0 解析会得到 `page_size=0` 这种荒谬值，
从而提出错误数据：

```
offset 8   : kernel_size
offset 12  : ramdisk_size      ← v4 没有 kernel_addr / ramdisk_addr
offset 16  : os_version
offset 20  : header_size       （实测 0x630 = 1584）
offset 40  : header_version    （= 4）
kernel 数据从 header_size 向上对齐到 4096 处开始
```

```python
import struct
d = open('boot-5.15.img','rb').read()
ksize, rsize, osver, hsize = struct.unpack('<IIII', d[8:24])
assert struct.unpack('<I', d[40:44])[0] == 4        # header_version
off = ((hsize + 4095) // 4096) * 4096
open('Image','wb').write(d[off:off+ksize])
```

`Image` 开头是 `4d 5a`（`MZ`）属正常 —— ARM64 + EFI stub 的形态。

### 验证镜像是否含符号（提取前先确认）

```bash
for s in commit_creds prepare_kernel_cred init_task init_cred; do
    printf "%-28s %s\n" "$s" "$(grep -c -a "$s" Image)"
done
# 再确认 kallsyms 相关字符串
strings -a Image | grep -E "kallsyms|__ksymtab" | head
```

vivo V27 实测：`commit_creds`×3、`prepare_kernel_cred`×2、`init_task`×2、
`init_cred`×1，且含 `__ksymtab`、`kallsyms.c` —— 镜像带完整符号表。

**直接喂给 `extract_rs` 即可**（无需 `--kallsyms`，它会自行从镜像恢复）：

```bash
ghostlock-extract boot-5.15.img --format json --out offsets.json
# info: kallsyms layout pre-6.4 recovered (158674 symbols)
# info: CVE-2026-43499 primitive present (remove_waiter@0x176e528 still uses current)
```

**注意**：`ghostlock-extract` 还会顺带在镜像里**验证漏洞原语是否还在**
（检查 `remove_waiter()` 是否仍使用 `current`）—— 相当于把"这台机器还有没有利用价值"
这件事也在同一步里做完了。

---

## 1. boot.img 与源码：先分清它们各自的用途

**这是最容易搞混的地方 —— 两者不是替代关系。**

| | **boot.img / init_boot.img** | **内核源码** |
|---|---|---|
| 含**符号地址** | ✅ 有（`extract_rs` 的核心输入） | ❌ 没有，需编译 |
| 含**结构体布局** | ⚠️ 需 BTF / DWARF 段 | ✅ 有 C 定义 |
| **与设备的版本匹配度** | ✅ **完全匹配** | ⚠️ 常有滞后（本次 5.15.74 vs 设备 5.15.178） |
| 体积 | 几十 MB | 200MB 源码（解压 1.2GB） |
| **获取难度** | **高**（见下） | **低** |
| 能否直接喂给 `extract_rs` | ✅ **可以** | ❌ 不可以 |

### boot.img 为什么常常拿不到

1. **块设备不可读** —— `/dev/block/by-name/*` 通常是 `root:root 0600`，未 root 读不了；
2. **要整包 OTA** —— 官方 OTA 往往是 10GB+ 的 payload/zip，而**只为了一个 `boot.img`**；
3. **第三方固件站不可信** —— 实测多个站点（nabafiles / mygsmrom / firmwaregenius 等）
   列出的文件**全部显示 `0 Downloads`**，且真实下载链接藏在 JS 交互或付费墙后，
   典型的诱饵站特征。**不要在这上面花时间。**
4. **A/B 分区** —— 现代设备是 `boot_a`/`boot_b`/`init_boot_a`/`vendor_boot_a`，
   没有裸 `boot`，容易看错；且 Android 13+ 内核常在 `init_boot` 或 `vendor_boot`。

> **但如果是 GKI 设备，这些都绕开** —— 见上方 §0.5：
> Google 的 `dl.google.com/android/gki/` 直接给 21MB 的 boot.img，不需要 root、
> 不需要 OTA、不需要厂商配合。**先确认是不是 GKI，再决定走哪条路。**

### 结论

```
GKI 设备        →  用 Google CDN（§0.5）★ 首选，21MB，符号 exact
非 GKI 设备     →
   能拿到 boot.img  →  优先用 boot.img（符号最准，直接可用）
   拿不到          →  退而用厂商开源站的源码，编译出 vmlinux 再喂给 extract_rs
最理想          →  两者都要：boot.img 给符号，源码给布局与补丁判定
```

## 2. 通用四步法：从官方开源站拿源码

### 第 1 步 · 找官方开源站

各厂商的入口（**记住关键词 `<厂商> open source`**）：

| 厂商 | 入口 |
|---|---|
| **vivo** | `opensource.vivo.com` |
| 小米 | `github.com/MiCode/Xiaomi_Kernel_OpenSource` |
| OPPO / 一加 / realme | `github.com/oppo-source` / `github.com/OnePlusOSS` |
| 三星 | `opensource.samsung.com` |
| 华为 | `consumer.huawei.com/minisite/opensource/` |
| 摩托罗拉 | `github.com/MotorolaMobilityLLC` |

**判断站点是否值得继续**：先 `curl` 首页看返回大小。

```bash
curl -sL -o page.html -w "%{http_code} %{size_download}\n" "<开源站URL>"
# 若只有几百字节且内容含 "doesn't work properly without JavaScript"
#   → 是 SPA，走第 2 步
```

### 第 2 步 · 从 JS bundle 里抠 API 清单

SPA 的接口都在它的 JS 里。以 vivo 为例：

```bash
# 首页 HTML 里能找到入口 JS
grep -oE 'src="[^"]*\.js"' page.html
#   → /js/chunk-vendors.<hash>.js  /js/index.<hash>.js

curl -s "<站点>/js/index.<hash>.js" -o app.js

# 抠出所有 API 路径与用途（中文 name 字段就是注释）
grep -oE 'url:"/[^"]+"' app.js
grep -oE '.{80}url:"/api/[^"]+".{80}' app.js
```

vivo 的关键接口（**实测**）：

```
POST /api/project/getProjectPage            项目列表（含覆盖机型）
POST /api/project/getPubSourceDownloadUrl   取公开源码下载链接
POST /api/project/getPriSourceDownloadUrl   取私有源码链接（一般用不到）
```

### 第 3 步 · 找真实调用代码（★ 最容易卡住的一步）

**API 清单只给出路径，参数名和格式在动态 chunk 里。**
把 chunk 清单抠出来、逐个下载、搜调用点：

```bash
# 从 app.js 里找 chunk 映射表  "chunk-XXXX":"<hash>"
grep -oE '"[a-zA-Z0-9_-]+":"[a-f0-9]{8}"' app.js

# 下载 chunk 后搜调用
grep -oE '.{120}(PubSource|DownloadUrl).{120}' chunk-*.js
```

vivo 的实战输出（决定性）：

```javascript
downloadSource: function(e, t) {
    var r = p["a"].project_project.getPubSourceDownloadUrl;
    "Private" === t.sourceType && (r = ...getPriSourceDownloadUrl),
    this.$fetch(r, b.a.stringify({projectSourceId: t.projectSourceId}))
                 ^^^^^^^^^^^^^^ ★ 参数格式
      .then(e => e.data ? window.open(e.data, "_blank") : ...)
}
```

**读到两件事**：
1. **参数名是 `projectSourceId`**
2. **格式是 `qs.stringify` → `application/x-www-form-urlencoded`，不是 JSON**

### 第 4 步 · 照抄它的请求

```bash
# ① 列项目
curl -s "https://opensource.vivo.com/api/project/getProjectPage" \
  -H "Content-Type: application/json;charset=UTF-8" \
  -X POST -d '{"pageNum":1,"pageSize":200}'
# → {"code":1,"data":{"total":125,"list":[{"id":..,"name":"android_13.0_kernel_mt6886",
#      "description":"V27,S17e", "projectSourceId":77, "sourceType":"Public"}, ...]}}

# ② 取下载链接 —— ★ 必须是 form-urlencoded
curl -s "https://opensource.vivo.com/api/project/getPubSourceDownloadUrl" \
  -H "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" \
  -H "Origin: https://opensource.vivo.com" \
  -H "Referer: https://opensource.vivo.com/Project" \
  -X POST -d "projectSourceId=77"
# → {"code":1,"data":"https://.../oss/uploader/download?token=<JWT>"}

# ③ 立刻下载（token 是 JWT，iat→exp 只有 ~600 秒）
curl -L -o kernel_src.tar.gz "<上一步的 data>"
```

**⚠️ token 有效期极短（实测 600 秒）**，所以「取链接」和「下载」必须写在同一条脚本里连续执行。

## 3. 实战记录（vivo V27 · 2026-09-11）

**设备**：`V2246` / `V2231`（vivo V27 5G），MT6886，内核 `5.15.178-android13-8-...`，
Android 15，`PD2269GF_EX_A_15.2.26.1.W20`，SELinux Enforcing。

**封锁情况（本地符号来源全灭）**：

| 路径 | 结果 |
|---|---|
| `/proc/kallsyms` | ❌ Permission denied |
| `/sys/kernel/btf/vmlinux` | ❌ Permission denied（尽管 `CONFIG_DEBUG_INFO_BTF=y`） |
| `/dev/block/by-name/{boot,init_boot,vendor_boot}_a` | ❌ Permission denied |
| `/proc/config.gz` | ✅ **可读**（6958 行，务必先存下来） |

**拿到的项目**：`android_13.0_kernel_mt6886`（`projectSourceId=77`，覆盖 V27/S17e）
—— **选它是因为设备内核是 android13 分支**。
另外三个相关项：`android_15.0_kernel_MT6886`(130)、`android_16.0_kernel_MT6886`(161)。

**结果**：两个包各约 195MB，**14 秒下完**（29MB/s），gzip 校验通过。

## 4. 拿到源码后的可行性判定

**这步的性价比极高 —— 不用编译就能判定机器能不能打。**

### 4.1 补丁状态（决定"还有没有价值"）

查 CVE 的**修复版本线**，与设备内核版本对比：

```
CVE-2026-43499 修复版本：5.10.261+ / 5.15.212+ / 6.1.175+ / 6.6.140+ / 6.12.86+
设备内核 5.15.178  < 5.15.212  →  未修复 ✅
```

**再用源码交叉验证**（本例读 `kernel/locking/rtmutex.c` 的 `remove_waiter()`）：

```c
raw_spin_lock(&current->pi_lock);      // ← vulnerable 形态（补丁后应为 waiter->task）
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;
```

这与 `extract_rs` 的判据一致（"fixed variant 不再含 `mrs xN, sp_el0`"）。

### 4.2 利用链前提（读设备 config）

```
CONFIG_FUTEX_PI=y                     ✅ 核心前提
CONFIG_KALLSYMS_ALL=y                 ✅ 内核带完整符号（只是运行时读不到）
CONFIG_RANDOMIZE_KSTACK_OFFSET        未启用 ✅ 栈偏移固定，有利
CONFIG_SLAB_FREELIST_RANDOM/HARDENED  =y    ⚠️ 堆随机化/加固
CONFIG_VMAP_STACK=y                   ⚠️ 栈走 vmalloc
```

### 4.3 源码包**不**包含什么

```
✗ vmlinux / System.map / Module.symvers   —— 纯源码树，无编译产物
✗ 内部结构体布局（如 rt_mutex_waiter）
     android/abi_gki_aarch64.xml 虽大（13.5MB），但它只记录 **ABI 可见的导出符号**，
     不含内核内部类型。实测其中查不到 rt_mutex_waiter / task_struct / mm_struct。
```

**所以要拿符号地址或精确偏移，只能编译（或另找 boot.img）。**

## 5. 编译源码需要什么

### 5.1 必需项

| 项 | 说明 |
|---|---|
| **编译器** | **必须与设备内核一致** —— 本例是 **AOSP clang 14.0.7**（`based on r450784e`），LLD 14.0.7。版本不一致会导致布局/代码生成差异，符号也就不可信 |
| **`.config`** | **直接用设备的 `/proc/config.gz`**（先存下来！）。它是最权威的配置，比猜 defconfig 可靠 |
| **构建工具** | `make`、`bc`、`bison`、`flex`、`libssl-dev`、`python3` |
| **aarch64 交叉目标** | `ARCH=arm64`、`CROSS_COMPILE=aarch64-linux-gnu-` |
| **磁盘/时间** | 解压后 1.2GB，编译产物数 GB；**30~60 分钟**量级 |
| **内存** | 建议 ≥ 16GB（`-j` 并发别开太大） |

### 5.2 典型命令形状

```bash
export ARCH=arm64
export PATH=<aosp-clang-14.0.7>/bin:$PATH
cp <设备 config.gz 解压后> .config
make CC=clang LLVM=1 LD=ld.lld AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy \
     OBJDUMP=llvm-objdump STRIP=llvm-strip olddefconfig
make CC=clang LLVM=1 ... -j$(nproc)               # 得到 vmlinux、System.map
```

### 5.3 麻烦在哪里（诚实清单）

1. **拿不到完全一致的 clang** —— AOSP prebuilt 的 14.0.7 需要单独下载；
   用 NDK 里的 clang 版本号对不上，**符号可信度下降**。
2. **源码与设备有版本差** —— 本例 5.15.74 vs 设备 5.15.178。
   即便编译成功，得到的符号也是「74 版」的，**不能直接当设备的符号表用**。
3. **厂商可能改过源码树** —— 有些厂商只放"基线 + 少量补丁"，或干脆放不完整的树。
4. **可能要补 `vendor` 代码** —— MTK/QCOM 驱动常来自闭源的 vendor 分支，缺了会编译失败。

### 5.4 所以现实的优先级

```
① 能拿 boot.img            → 不要编译，直接用（符号 exact，几分钟搞定）
② 拿不到，但源码版本吻合   → 编译（值得）
③ 拿不到，且源码版本有差   → 编译只能得到"近似符号"，
                            更适合用来推导**结构体布局**，
                            地址仍需靠 extract_rs 的 kallsyms_finder 从镜像恢复
```

## 6. 与其他方案的关系

| 方案 | 需要什么 | 本文相关 |
|---|---|---|
| A · 设备已 root | `su` 读 kallsyms | 见 `VULN_SCOPE.md` §四 |
| B · 设备自带 BTF | `/sys/kernel/btf/vmlinux` 可读 | vivo 上被拒 |
| **C · OTA / 工厂包** | 官方包 | **本文第 2 节（源码）是其可行替代** |
| D · dd 分区 | root 或可读块设备 | vivo 上被拒 |
| E · 源码 + 配置重建 | **官方开源站** | **本文主题** |
