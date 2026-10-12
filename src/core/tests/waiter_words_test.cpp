#include "route/route_api.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>

#include "kernel/waiter_layout.hpp"

using namespace ghostlock;

namespace {
    constexpr uintptr_t kTarget = 0xffffff880c0a1a10ULL;
    constexpr uintptr_t kFakeRight = 0xffffff802a7a0930ULL;
    constexpr uintptr_t kFakeTask = 0xffffff87e97c0400ULL;
    constexpr uintptr_t kFakeLock = 0xffffff87e97c0000ULL;

    const route::WaiterWord *find_word(
        const route::WaiterWord *words, size_t count, int32_t word) {
        for (size_t i = 0; i < count; i++) {
            if (words[i].word == word) return &words[i];
        }
        return nullptr;
    }
} // namespace

int32_t main(void) {
    route::WaiterWord words[16]{};

    /* --- 5.10 compact, value write (preserve_child == 1): fake_right is the
     * value, so the relink parents on it and relinks left at the target.
     * This is the W1/W2 shape already verified on the device and it must stay
     * byte-identical. --- */
    {
        const size_t count = route::select_stack_waiter_words(
            kernel::COMPACT_WAITER_5_10, kTarget, kFakeRight, kFakeTask,
            kFakeLock, words, std::size(words));
        assert(count == 10);
        /* Word 12 (0x50) does not exist on 5.10: the waiter ends at 0x50. */
        assert(find_word(words, count, 12) == nullptr);
        assert(find_word(words, count, 2)->value == kFakeRight);
        assert(find_word(words, count, 5)->value == kFakeRight);
        assert(find_word(words, count, 4)->value == kTarget);
        assert(find_word(words, count, 7)->value == kTarget);
        assert(find_word(words, count, 3)->value == 0);
        assert(find_word(words, count, 6)->value == 0);
        assert(find_word(words, count, 8)->value == kFakeTask);
        assert(find_word(words, count, 9)->value == kFakeLock);
        assert(find_word(words, count, 10)->value ==
               static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO));
        assert(find_word(words, count, 11)->value == 0);
    }

    /* --- 5.10 compact, leaf write (preserve_child == 0, i.e. W3): fake_right is
     * zero, so pc must fall back to target - 8 instead of leaving the node
     * parentless. relinking left at 0 is what layout.left (never assigned)
     * encodes on the payload side. --- */
    {
        const size_t count = route::select_stack_waiter_words(
            kernel::COMPACT_WAITER_5_10, kTarget, 0, kFakeTask, kFakeLock, words,
            std::size(words));
        assert(count == 10);
        assert(find_word(words, count, 2)->value == kTarget - 8);
        assert(find_word(words, count, 5)->value == kTarget - 8);
        assert(find_word(words, count, 4)->value == 0);
        assert(find_word(words, count, 7)->value == 0);
        /* A parentless node is the failure this arm exists to prevent. */
        assert(find_word(words, count, 2)->value != 0);
        assert(find_word(words, count, 5)->value != 0);
        assert(find_word(words, count, 8)->value == kFakeTask);
        assert(find_word(words, count, 9)->value == kFakeLock);
    }

    /* --- The leaf fallback matches what encode_compact_waiter() writes into
     * pi_tree_entry for the same request: 0x18 = target - 8, 0x20 = 0,
     * 0x28 = layout.left (always 0). Word 5 is pi_tree_entry.rb_parent_color
     * and word 7 is pi_tree_entry.rb_left. --- */
    {
        const memory::WriteRequest request = memory::WriteRequest::make(
            kTarget, memory::WriteMode::Zero, /*leaf=*/true);
        assert(request.preserve_child == false);
        assert(request.target == kTarget);
        const size_t count = route::select_stack_waiter_words(
            kernel::COMPACT_WAITER_5_10, request.target, 0, kFakeTask, kFakeLock,
            words, std::size(words));
        assert(count == 10);
        assert(find_word(words, count, 5)->value == request.target - 8);
        assert(find_word(words, count, 7)->value == 0);
    }

    /* --- 6.1 compact is untouched by the leaf fallback: it keeps its own
     * table, including ww_ctx at word 12. --- */
    {
        const size_t count = route::select_stack_waiter_words(
            kernel::COMPACT_WAITER_6_1, kTarget, kFakeRight, kFakeTask,
            kFakeLock, words, std::size(words));
        assert(count == 11);
        assert(find_word(words, count, 2)->value == kFakeRight);
        assert(find_word(words, count, 4)->value == kTarget);
        assert(find_word(words, count, 10)->value ==
               ((static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO) << 32) | 3));
        assert(find_word(words, count, 12) != nullptr);
        assert(find_word(words, count, 12)->value == 0);
    }

    /* --- 6.6 rb_node layout: 13 words, ends at wake_state (word 14). --- */
    {
        const size_t count = route::select_stack_waiter_words(
            0, kTarget, kFakeRight, kFakeTask, kFakeLock, words,
            std::size(words));
        assert(count == 13);
        assert(find_word(words, count, 12)->value == kFakeTask);
        assert(find_word(words, count, 13)->value == kFakeLock);
        assert(find_word(words, count, 14)->value == 3);
    }

    /* --- A short buffer reports 0 and writes nothing: the caller must notice
     * rather than place a partial waiter. --- */
    {
        route::WaiterWord small[4]{};
        assert(route::select_stack_waiter_words(
                   kernel::COMPACT_WAITER_5_10, kTarget, kFakeRight, kFakeTask,
                   kFakeLock, small, std::size(small)) == 0);
        assert(small[0].word == 0 && small[0].value == 0);
        assert(route::select_stack_waiter_words(
                   kernel::COMPACT_WAITER_5_10, kTarget, kFakeRight, kFakeTask,
                   kFakeLock, nullptr, 16) == 0);
    }

    puts("waiter_words_test: ok");
    return 0;
}
