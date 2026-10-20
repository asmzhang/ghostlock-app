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

## Appendix (2026-10-20, later): FUTEX_LOCK_PI parking — geometrically dead

Re-parked the waiter via `FUTEX_LOCK_PI` (5.10 `futex_lock_pi`, stock file
0x2788BC, frame 0x130, `rt_waiter` at `sp+0x78`, x24 = x29-0x58, self-referencing
`RB_CLEAR` init at 0x278970/0x278980) to escape the 5.10 requeue-Pi kernel
rewrites. Fit formula (validated on A301SO hardware for the requeue variant):
`waiter_local = ss_depth - waiter_depth` must satisfy
`waiter_local + 0x38 + 8 <= buffer_size (0x108)`.

- lock_pi parking: `Σfx = 0x90+0x130+0x130 = 0x2F0`, local 0x78 ⇒
  `waiter_depth = 0x278`. IPv4 stamp (`MCAST_BLOCK_SOURCE`, greqs@0x18 in
  ip_setsockopt 0x290): `ss_depth = 0x358` ⇒ `waiter_local = 0xE0`;
  `0xE0+0x40 = 0x120 > 0x108` — task/lock fields stick out 24 bytes. Dead.
- No shallower IPv4 path exists: every proto hook adds a non-negative frame to
  `0x348+X`; lock_pi needs `ss_depth <= 0x340`. Impossible for any X >= 0.
- IPv6 measured (one-off probe `tools/extract_rs/src/bin/p6_ipv6_probe.rs`,
  kept as evidence): `udpv6_setsockopt` 0x40 + `ipv6_setsockopt` 0x40 +
  `do_ipv6_setsockopt` 0x2C0 (preindex 0x60 + sub 0x260), greqs local 0x40
  (two `mov w2,#0x108` sites at 0x1540B34/0x1540B58, both fed by
  `add x0,sp,#0x40`) ⇒ `ss_depth6 = 0x3F0`. lock_pi local = 0x178 (worse);
  even requeue_pi would be 0x120 > 0x108 (worse). `rawv6_setsockopt` (frame
  0x50) calls do_ipv6_setsockopt directly: Σ=0x440, even deeper. All IPv6
  variants dead.
- Conclusion: every 0x108-stamp route is geometrically closed for lock_pi
  parking on oriole. The requeue-Pi parking remains the only window-fitting
  shape (0x88) and is blocked by the kernel rewrites in the mechanism section
  above. The only remaining candidate stays the cross-attempt stack reuse.

## Artifacts

- Batch: `build/510profile/rounds-p6-b1/` (20 rounds + kernel.log)
- Gate chain: 2026-10-19-pixel6-root-forensics.md (root + address model fixes)
- Code state: variant B + 5.10 multicast encode kept in tree (threads.cpp,
  payload_builder, multicast_waiter_route.cpp); see commit following this doc.
