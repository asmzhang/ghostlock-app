/* 探测 TCP zerocopy 路线在当前内核上是否可用。
 *
 * 背景：GhostLock 有两条 reclaim 路线——
 *   · pselect：pselect 把 fd_set 拷到内核栈，可覆盖 stale waiter
 *   · TCP    ：getsockopt(TCP_ZEROCOPY_RECEIVE) 把 zc 拷到内核栈，可覆盖 stale waiter
 * exploit 需要写到 zc 偏移 0x28（waiter->task）与 0x30（waiter->lock），
 * 所以**内核编译期的 sizeof(struct tcp_zerocopy_receive) 必须 >= 0x38**。
 * 5.10 上它只有 0x28，于是 0x28/0x30 两个字根本不会被 copy_from_user 拷进来，
 * getsockopt 直接 EINVAL —— 这就是 5.10 必须走 pselect 的原因。
 *
 * 本探针不改任何东西，只做一次 getsockopt，观察内核把 optlen 回写成多少、
 * 以及用户缓冲区哪些字节被内核写过，据此推断内核 struct 的真实大小。
 *
 * 编译（aarch64 android）：
 *   NDK=$ANDROID_HOME/ndk/<ver>/toolchains/llvm/prebuilt/windows-x86_64/bin
 *   $NDK/aarch64-linux-android35-clang -O2 -o probe_tcp_route probe_tcp_route.c
 * 运行（无需 root）：
 *   adb push probe_tcp_route /data/local/tmp/ && adb shell /data/local/tmp/probe_tcp_route
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE 35
#endif

/* 我们关心 exploit 需要写到多远 */
#define NEED_OFFSET 0x38
#define PROBE_LEN 0x48     /* 故意比任何已知 struct 都大 */
#define SENTINEL 0xA5

static int make_tcp_pair(int *srv, int *cli) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return -1;
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) < 0) { close(ls); return -1; }
    if (listen(ls, 1) < 0) { close(ls); return -1; }
    socklen_t al = sizeof(a);
    if (getsockname(ls, (struct sockaddr *)&a, &al) < 0) { close(ls); return -1; }
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) { close(ls); return -1; }
    if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) { close(c); close(ls); return -1; }
    int s = accept(ls, NULL, NULL);
    close(ls);
    if (s < 0) { close(c); return -1; }
    *srv = s; *cli = c;
    return 0;
}

int main(void) {
    printf("sizeof(struct tcp_zerocopy_receive) 按本机头文件 = 0x%zx\n",
           sizeof(struct tcp_zerocopy_receive));
    printf("exploit 需要覆盖到偏移 0x%x\n\n", NEED_OFFSET);

    int srv = -1, cli = -1;
    if (make_tcp_pair(&srv, &cli) != 0) {
        printf("建 loopback TCP 连接失败: %s\n", strerror(errno));
        return 2;
    }

    /* 喂一点数据，让 socket 进入可接收状态 */
    (void)!write(cli, "hello-ghostlock", 15);

    /* 一个页对齐的 zerocopy 目标区 */
    size_t pg = 4096;
    void *map = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) { printf("mmap 失败\n"); close(srv); close(cli); return 2; }

    unsigned char buf[PROBE_LEN];
    memset(buf, SENTINEL, sizeof(buf));
    *(uint64_t *)&buf[0] = (uint64_t)(uintptr_t)map;   /* zc.address */
    *(uint32_t *)&buf[8] = (uint32_t)pg;               /* zc.length  */

    /* optlen 只能当"回写值"读，而内核可能提前 return（EINVAL/EFAULT）而不回写。
     * 此时用户态的 len 保持我们传入的输入长度 —— 与"内核 struct 正好等于该值"
     * 无法区分。单次调用因此是**无效测量**：上一版就据此把 0x48（我们自己的输入）
     * 当成"5.15 实测 sizeof"，并写进了 exploit 的注释。
     * 用两次不同请求长度消歧：若内核会回写，第二次必然给出同一个（被截断的）
     * sizeof；若两次都等于各自的输入，则说明根本没有回写。 */
    unsigned char buf2[0x100];
    socklen_t len2 = sizeof(buf2);
    memset(buf2, SENTINEL, sizeof(buf2));
    *(uint64_t *)&buf2[0] = (uint64_t)(uintptr_t)map;
    *(uint32_t *)&buf2[8] = (uint32_t)pg;

    socklen_t len = sizeof(buf);                       /* 故意偏大 */
    errno = 0;
    int ret = getsockopt(cli, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, buf, &len);
    int e = errno;

    errno = 0;
    int ret2 = getsockopt(cli, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, buf2, &len2);
    int e2 = errno;

    printf("getsockopt(请求 0x%zx) 返回 = %d, errno = %d (%s), optlen -> 0x%x\n",
           sizeof(buf), ret, e, strerror(e), (unsigned)len);
    printf("getsockopt(请求 0x%zx) 返回 = %d, errno = %d (%s), optlen -> 0x%x\n",
           sizeof(buf2), ret2, e2, strerror(e2), (unsigned)len2);

    if ((size_t)len == sizeof(buf) && (size_t)len2 == sizeof(buf2)) {
        printf("\n⚠️  两次 optlen 都等于各自的请求长度 ⇒ **内核根本没有回写 optlen**\n");
        printf("    (说明调用在 put_user 之前就返回了)。本次测量无效，不能推出\n");
        printf("    sizeof(struct tcp_zerocopy_receive)；请改看源码或设备 BTF。\n");
    } else {
        printf("\n回写有效 ⇒ 内核 sizeof(struct tcp_zerocopy_receive) = 0x%zx\n",
               (size_t)len2);
    }

    /* 内核动过的字节有哪些（排除我们写进去的 address/length 两个字段） */
    printf("\n内核改写过的字节：\n");
    int touched_high = -1, n = 0;
    for (size_t i = 0x10; i < sizeof(buf); i++) {
        if (buf[i] != SENTINEL) {
            printf("  buf[0x%02zx] = 0x%02x\n", i, buf[i]);
            touched_high = (int)i;
            n++;
        }
    }
    if (!n) printf("  （无 —— 内核一个字节都没回写）\n");

    /* 判定：optlen 的回写值是权威 —— do_tcp_getsockopt 里有
     *   if (len > sizeof(zc)) len = sizeof(zc);  ...  if (put_user(len, optlen))
     * 所以内核把请求长度截断到自己的 struct 大小后写回 optlen。
     * 注意 touched_high 为 -1（无回写）时**不能**直接转 size_t 比较，
     * 那会变成 SIZE_MAX 而误判为"可用"（第一版就是这么错的）。 */
    /* 只有确认回写有效时，len2 才能当 sizeof 用 */
    int writeback_ok = !((size_t)len == sizeof(buf) &&
                         (size_t)len2 == sizeof(buf2));
    size_t ksize = writeback_ok ? (size_t)len2 : 0;

    printf("\n判定：\n");
    if (!writeback_ok) {
        printf("  ❔ 测量无效（optlen 未回写）—— 本探针无法给出 sizeof。\n");
        printf("     请以源码为准：5.15 的 include/uapi/linux/tcp.h 定义\n");
        printf("     msg_control@0x28 / msg_controllen@0x30，sizeof = 0x40。\n");
    } else if (ksize < NEED_OFFSET) {
        printf("  ❌ 内核 struct 只有 0x%zx，够不到 exploit 需要的 0x%x\n",
               ksize, NEED_OFFSET);
        printf("     → TCP 路线**不可用**，必须用 pselect\n");
    } else if (touched_high >= 0 && (size_t)touched_high >= 0x28) {
        printf("  ✅ 内核 struct = 0x%zx 且实测有字节写到 0x%x —— TCP 路线可用\n",
               ksize, touched_high);
    } else {
        printf("  ⚠️  内核 struct = 0x%zx（够大），但本次无回写 ——\n", ksize);
        printf("     可能是 address 未通过 find_vma 校验而提前返回；\n");
        printf("     此情形下 TCP 路线的可用性需用真实 zerocopy VMA 再测。\n");
    }
    printf("\n  （参考：5.10 GKI 实测 optlen=0x28，故 0x28/0x30 两字拷不进来）\n");

    munmap(map, pg);
    close(srv);
    close(cli);
    return 0;
}
