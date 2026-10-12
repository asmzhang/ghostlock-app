/*
 * GhostLock — /proc/<tid>/syscall snapshot parser (path A gate).
 *
 * The three shapes below are copied verbatim from the kernel printer
 * (fs/proc/base.c, proc_pid_syscall()) and from a marble device running
 * 5.10.149, where a thread parked in pselect(320, ...) reported the nine-field
 * form with the syscall number first.
 */

#include "../support/syscall_snapshot.hpp"

#include <cassert>
#include <cstdio>

using namespace ghostlock;

int32_t main(void) {
    /* Sleeping inside pselect6: the only shape that counts as confirmed. */
    const support::SyscallSnapshot parked = support::parse_syscall_snapshot(
        "72 0x140 0x708593dbb0 0x708593db30 0x708593dab0 0x708593da00 "
        "0x708593da10 0x708593da00 0x71062ffc7c");
    assert(parked.kind == support::SyscallSnapshotKind::Sleeping);
    assert(parked.number == 72);

    /* Sleeping inside a different syscall: parseable, but not our target. */
    const support::SyscallSnapshot other = support::parse_syscall_snapshot(
        "101 0x7fd7ba8f58 0x0 0xa 0x0 0x80000000 0xa070d3e00000000 0x7fd7ba8f50 "
        "0x746d1a435c");
    assert(other.kind == support::SyscallSnapshotKind::Sleeping);
    assert(other.number == 101);

    /* The task is on-cpu, or its state changed while it was sampled. */
    assert(support::parse_syscall_snapshot("running").kind ==
           support::SyscallSnapshotKind::Running);
    assert(support::parse_syscall_snapshot("running\n").kind ==
           support::SyscallSnapshotKind::Running);

    /* nr < 0: no live syscall number, so nothing can be confirmed from it. */
    const support::SyscallSnapshot faulted =
        support::parse_syscall_snapshot("-1 0xffffffc0102a4f10 0xffffffc0102a3f20");
    assert(faulted.kind == support::SyscallSnapshotKind::Faulted);
    assert(faulted.number == -1);

    /* The literal read_first_line() leaves behind when the file cannot be
     * opened, plus other text that is not a snapshot at all. */
    assert(support::parse_syscall_snapshot("unreadable").kind ==
           support::SyscallSnapshotKind::Unreadable);
    assert(support::parse_syscall_snapshot("").kind ==
           support::SyscallSnapshotKind::Unreadable);
    assert(support::parse_syscall_snapshot(nullptr).kind ==
           support::SyscallSnapshotKind::Unreadable);
    assert(support::parse_syscall_snapshot("do_select").kind ==
           support::SyscallSnapshotKind::Unreadable);

    /* A number without the full argument dump is never a confirmation: the
     * two-field form belongs to nr < 0 only. */
    assert(support::parse_syscall_snapshot("72 0x140").kind ==
           support::SyscallSnapshotKind::Unreadable);
    /* Trailing garbage means a torn read. */
    assert(support::parse_syscall_snapshot("72 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 x")
               .kind == support::SyscallSnapshotKind::Unreadable);
    /* A field that is not a hex literal. */
    assert(support::parse_syscall_snapshot("72 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0xzz")
               .kind == support::SyscallSnapshotKind::Unreadable);
    /* Out-of-range numbers must not wrap into a plausible syscall number. */
    assert(support::parse_syscall_snapshot(
               "99999999999 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8")
               .kind == support::SyscallSnapshotKind::Unreadable);

    puts("syscall_snapshot_test: ok");
    return 0;
}
