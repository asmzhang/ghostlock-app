/*
 * GhostLock — parser for the `/proc/<tid>/syscall` snapshot.
 *
 * The kernel prints exactly one of three shapes (fs/proc/base.c,
 * proc_pid_syscall()):
 *
 *   running
 *   <nr> 0x<sp> 0x<ip>                             (nr < 0, no live number)
 *   <nr> 0x<a0> .. 0x<a5> 0x<sp> 0x<ip>            (the task is asleep)
 *
 * Only the third shape proves the target thread is parked inside a syscall,
 * and only its first field says which one. Parsing lives here, apart from the
 * read, so host tests can pin all three shapes without a /proc.
 */

#ifndef GHOSTLOCK_SUPPORT_SYSCALL_SNAPSHOT_HPP
#define GHOSTLOCK_SUPPORT_SYSCALL_SNAPSHOT_HPP

#include <cstdint>

namespace ghostlock::support {
    enum class SyscallSnapshotKind : int32_t {
        Unreadable = 0, /* open/read failed, or the text is not a snapshot */
        Running,        /* on-cpu, or the state changed while it was sampled */
        Faulted,        /* nr < 0: no live syscall number to report */
        Sleeping,       /* nine fields: the task is parked inside `number` */
    };

    struct SyscallSnapshot final {
        SyscallSnapshotKind kind = SyscallSnapshotKind::Unreadable;
        int32_t number = -1;
    };

    [[nodiscard]] constexpr bool is_hex_digit(char c) noexcept {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }

    /* Parses one snapshot line; a trailing newline is allowed. Anything that
     * is not one of the three shapes comes back Unreadable, so a caller that
     * waits for a specific syscall number keeps waiting instead of acting on
     * a guess. */
    [[nodiscard]] inline SyscallSnapshot parse_syscall_snapshot(const char *text) noexcept {
        if (!text) {
            return SyscallSnapshot{};
        }
        const char *p = text;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        /* "running" is the only non-numeric first word the kernel prints. */
        if (p[0] == 'r' && p[1] == 'u' && p[2] == 'n' && p[3] == 'n' &&
            p[4] == 'i' && p[5] == 'n' && p[6] == 'g') {
            return SyscallSnapshot{.kind = SyscallSnapshotKind::Running, .number = -1};
        }
        bool negative = false;
        if (*p == '-') {
            negative = true;
            p++;
        }
        if (*p < '0' || *p > '9') {
            return SyscallSnapshot{};
        }
        int64_t magnitude = 0;
        while (*p >= '0' && *p <= '9') {
            magnitude = magnitude * 10 + static_cast<int64_t>(*p - '0');
            if (magnitude > 0x7fffffff) {
                return SyscallSnapshot{};
            }
            p++;
        }
        const int32_t number = negative ? -static_cast<int32_t>(magnitude)
                                        : static_cast<int32_t>(magnitude);
        /* Count the "0x..." fields that follow the syscall number. */
        int32_t fields = 0;
        for (;;) {
            while (*p == ' ' || *p == '\t') {
                p++;
            }
            if (p[0] != '0' || (p[1] != 'x' && p[1] != 'X')) {
                break;
            }
            p += 2;
            if (!is_hex_digit(*p)) {
                return SyscallSnapshot{};
            }
            while (is_hex_digit(*p)) {
                p++;
            }
            fields++;
        }
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p != 0 && *p != '\n' && *p != '\r') {
            return SyscallSnapshot{};
        }
        if (number < 0) {
            return SyscallSnapshot{.kind = SyscallSnapshotKind::Faulted, .number = number};
        }
        if (fields != 8) {
            return SyscallSnapshot{};
        }
        return SyscallSnapshot{.kind = SyscallSnapshotKind::Sleeping, .number = number};
    }
} // namespace ghostlock::support

#endif
