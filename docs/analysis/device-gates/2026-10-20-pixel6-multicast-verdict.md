# Pixel 6 multicast route: 0/20 write-landing verdict (2026-10-20)

## Verdict

The multicast_waiter route **cannot land W1 on oriole 5.10.157** (android13-4 GKI).
20/20 batch rounds (`build/510profile/rounds-p6-b1/summary.txt`) show the identical
all-green route / no-write shape:

- `CMP_REQUEUE_PI ret=1 errno=0` (variant B: owner holds target, chain edge deferred)
- `WAIT_REQUEUE_PI ret=-1 errno=110` (waiter wakes via timeout, not via consume)
- `multicast route status=0 clean=1/1 step=0 errno=0`
- `[-] Write 1 failed`; `/sys/fs/selinux/enforce` polls 1 at 0.5 s cadence throughout
- zero reboots (oriole misses are benign, unlike marble), fork-hold ok every round

## Mechanism (why the write never lands)

Three kernel-side rewrites kill every pre-seeded overlay path on 5.10:

1. `rt_mutex_init_waiter` (5.10) rewrites `tree_entry`, `pi_tree_entry`, `task`
   -> any overlay planted before `FUTEX_WAIT_REQUEUE_PI` is erased.
2. `task_blocks_on_rt_mutex` (:951-975) rewrites `task/lock/prio/deadline` and the
   tree links -> even a successfully enqueued waiter gets its crafted fields
   replaced by real ones.
3. The only crafted bytes that survive are the reclaim-skb page writes
   (`prepare_skb_payload`), but they land on the leaked page, not on the futex
   stack frame where `rt_waiter` lives.

Variant A (TID-0 takeover, owner unlocks target before CMP) proved the requeue
WAKE path opens (`CMP ret=1 + WAIT ret=0`) but `requeue_pi_wake_futex` sets
`q->rt_waiter = NULL` and the kernel never touches the crafted bytes
(futex-v5.10.149.c:1812, :3243). Variant B proved the enqueue path can be reached
without EDEADLK (chain edge deferred), but the enqueued waiter is then fully
owned/rewritten by the kernel. The upstream multicast success (A301SO, 5.15.189)
rides a 5.15-specific stack-frame coincidence we did not reproduce; 5.15 rtmutex
differs substantially.

## What is NOT invalidated

- The CVE-2026-43499 primitive itself: `remove_waiter@0x1da38c` is unpatched in
  oriole 5.10.157 (extractor --analysis), and the exploit is proven end-to-end on
  marble 5.10.149 (uid=0 60-70%, KernelSU 70%, APatch 2/2).
- select_stack on oriole was ruled out earlier by geometry: do_futex frame 0x130
  vs marble 0x70 puts the waiter 24 qwords below the fd_set-controlled window
  (derive.rs frame dump, b476).

## Remaining unexplored (kept for the record, not scheduled)

- Cross-attempt kernel stack reuse: reclaim-sends writing crafted bytes into the
  leaked page that a LATER attempt's rt_waiter occupies. Requires multi-attempt
  plumbing on multicast (W1 attempts currently forced to 1 for multicast,
  backend.cpp:444-447) and is speculative.

## Artifacts

- Batch: `build/510profile/rounds-p6-b1/` (20 rounds + kernel.log)
- Gate chain: 2026-10-19-pixel6-root-forensics.md (root + address model fixes)
- Code state: variant B + 5.10 multicast encode kept in tree (threads.cpp,
  payload_builder, multicast_waiter_route.cpp); see commit following this doc.
