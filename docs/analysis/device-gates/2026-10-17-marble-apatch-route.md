# APatch route on marble: from zero to `su -c id` = u:r:magisk:s0

Date: 2026-10-17 · Device: marble `3e6f1443` (Redmi Note 12 Turbo, 5.10.149-android12-9-00001-gda3d81545d1d-ab9545656) · Branch `main-510-port`

## Verdict

User asked (m16030): "我不在电脑前，Pixel 6 先停，将APatch解决".

**Done.** One full in-app run stages and loads `kernelpatch.ko` through APatch's
`apd insmod`, survives the soft-reboot, and `su -c id` returns
`uid=0(root) ... context=u:r:magisk:s0` — the real APatch root, manager-independent.

## Three blockers found on the way, all fixed

### 1. Kotlin release check never matched (fixed earlier, worth recording)

`prepareKpatch` originally gated on `release.contains("-5.10.")`, but marble's
`os.version` = `5.10.149-android12-9-...` has no leading dash → the `.ko` was
never staged. Fixed to `contains("5.10.")`. (commit a82dc55 line of work)

### 2. Prebuilt W3-0 page reported `base=0` (commit 4a13a29)

`prepare_prebuilt_leaf_page` kept `prepare_good_kernel_page`'s return value in
a local, but `PayloadPage::move_to` copies `heap.current.base` verbatim into
prebuilt → the activated page showed
`pselect route missing kernel page base=0000000000000000 lock=... fops=...`
(status=2 step=30, `rounds-apatch2` round 1) and W3-0 fell back to a fresh
spray. `attack_write` owns the base store on the regular path
(`cve_2026_43499_backend.cpp:519`); the prebuild path must do the same before
`stash_prebuilt_page()`. After the fix the prebuilt page activates cleanly
("heap spray skipped (prebuilt W3-0 page activated)") — same behavior as the
KernelSU batches.

### 3. The root script never reached the APatch arm (commit 26a3d84f lineage)

`case "$KSUD"` matched `*libapd.so)` only when KSUD pointed at apd — but the
app **always** stages `ksud` into HOME_DIR, so KSUD resolved to the KernelSU
binary and `ksud late-load` pulled in the **kernelsu** module on an APatch-only
device (`rounds-apatch3` round 2 ksu-log: `late-load exit=0`, `/proc/modules`
showed `kernelsu`, `kernelpatch` count 0).

Fix: loader chosen by capability, not by which binary matched first —

```sh
LOADER="$KSUD"
if [ -x "$APD" ]; then
  if [ -f "$APKO" ] || ls /data/local/tmp/*kernelpatch*.ko >/dev/null 2>&1; then
    LOADER="$APD"
  fi
fi
case "$LOADER" in
  *libapd.so)  ... "$LOADER" insmod "$APKO" ... ;;
  *)           ... "$LOADER" late-load --kmi "$KMI" --allow-shell ... ;;
esac
```

APatch wins when apd AND a kernelpatch .ko are both staged; KernelSU keeps the
fallback and stays byte-identical when APatch is absent.

### Harness false positive (trials_ps4 v4.13)

`hold=ok(ksu-log)` read a **stale** `ghostlock-ksu-*.log` from the previous
batch (`rounds-apatch4` round 6: W3 stuck in pselect, but the verdict said
HIT-ROOT via last batch's script log). Per-round cleanup now also removes
`files/ghostlock-ksu-*.log` and `files/.ghostlock_sh_probe`.

## Winning run (rounds-apatch5, round 2, 17:09)

Cold boot, in-app run, no PC involvement:

```
child uid = 0 / child is root!
W3-0 page prebuilt ok / heap spray skipped (prebuilt W3-0 page activated)
W3: TIF_SECCOMP + seccomp mode cleared → seccomp fully bypassed
handoff: script open fd=320 → root script starts uid=0 euid=0, Seccomp: 0
apd=/data/user/0/com.ghostlock.app/files/libapd.so
apko=/data/user/0/com.ghostlock.app/files/kernelpatch.ko (183312 B)
policy fixup rc=0 → apd insmod kmi=android12-5.10 ko=.../kernelpatch.ko
Loaded kernel module: /data/data/com.ghostlock.app/files/kernelpatch.ko
apd insmod rc=0 → [+] KernelSU module loaded
```

Then `tools/trials/apatch_finish.ps1` (my2-proven sequence): kernelpatch Live
confirmed → `apd soft-reboot` (kernel keeps the module) → `resetprop
sys.boot_completed 1` → manager restart → **`su -c id` = uid=0(root) gid=0(root)
... context=u:r:magisk:s0**.

Device never hard-rebooted through the whole sequence (soft-reboot only restarts
the framework; uptime continuity preserved except the deliberate soft-reboot).

## Binaries

- native `build/native/ghostlock` md5 `6168B54AC88EFE8512EEE6DB962C17B4` (base fix) → final loader build rebuilt APK `GhostLock-v1.2(587)-arm64-v8a-debug.apk` md5 `36DD77F0E808EF6D2CDFC635130D500D`
- host tests WSL `bash build/run_host_tests_510.sh`: build_fail=0 run_fail=0 (27/27), `backend_dataflow_test: ok`

## Remaining known gaps (unchanged from KernelSU route)

- pselect miss family (W1 ~75% / W2 80% conditional) still ends in a reboot on
  marble's `panic_on_oops=1` — orthogonal to the APatch handoff, tracked as the
  standing "miss ⇒ device dies" objective (user keeps it parked).
- W3 conditional 59% in the 40-round audit: on stuck rounds the leaf/TIF/mode
  writes hang in pselect; device survives but no handoff.

## Commits

- `4a13a29` fix(5.10): store the prebuilt W3-0 base before stashing
- (this one) feat(5.10): APatch loader selection + stale-log trial fix
