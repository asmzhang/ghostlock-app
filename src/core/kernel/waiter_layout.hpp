#ifndef GHOSTLOCK_KERNEL_WAITER_LAYOUT_HPP
#define GHOSTLOCK_KERNEL_WAITER_LAYOUT_HPP

#include <cstdint>

/* Waiter layouts the fake-lock routes know how to stamp.
 *
 * The ordinal travels in the profile's `compact_waiter` key. Upstream shipped it
 * as a boolean ("is this a compact rt_mutex_waiter"), so 0 still means the
 * 6.6 rb_node layout and 1 still means 6.1. Value 2 is the 5.10 compact layout,
 * which is a third shape rather than a variant of 6.1:
 *
 *   0 (or absent) 6.6   tree_entry/pi_tree_entry are rb_node:
 *                       __rb_parent_color@0x00 rb_right@0x08 rb_left@0x10
 *                       + prio/deadline after each node, wake_state last.
 *   1             6.1   compact: tree_entry@0x00, pi_tree_entry@0x18,
 *                       task@0x30, lock@0x38, wake_state@0x40 | prio@0x44,
 *                       deadline@0x48, ww_ctx@0x50.
 *   2             5.10  compact: tree_entry@0x00, pi_tree_entry@0x18,
 *                       task@0x30, lock@0x38, prio@0x40, deadline@0x48.
 *                       There is no wake_state and no ww_ctx, so the structure
 *                       ends at 0x50 and the last fd_set word 6.1 uses (0x50)
 *                       does not exist here.
 *
 * This header deliberately does not include kernel/offset.h: the ordinal and the
 * fake-waiter priority are pure numbers, and host tests must be able to assert
 * the per-layout word tables without pulling in the TARGET_CONFIG_H-dependent
 * offset table.
 */
namespace ghostlock::kernel {
    /* Must stay above FAKE_TASK_PRIO (120): the erase relink's PI walk only takes
 * the branch this payload relies on for a higher-priority ghost waiter. */
    inline constexpr int32_t FAKE_WAITER_PRIO = 140;

    inline constexpr uint8_t COMPACT_WAITER_6_1 = 1;
    inline constexpr uint8_t COMPACT_WAITER_5_10 = 2;
} // namespace ghostlock::kernel

#endif
