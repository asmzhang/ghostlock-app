/* 5.10.149-android12-9-00001-gda3d81545d1d-ab9545656
 *
 * Redmi Note 12 Turbo (marble) / SM7475 WAIPIO, MIUI V14.0.27.0.TMRCNXM.
 * Baseline: Xiaomi marble-s-oss (5.10.117) + vendor patches.
 *
 * Struct offsets derived from AOSP GKI 5.10 arm64 vmlinux BTF
 * (kernel/prebuilts/5.10/arm64, kernel-5.10). Symbol offsets recovered
 * from the device boot.img kallsyms table (pre-6.4 layout).
 *
 * rt_mutex_waiter is the 5.10 compact layout (tree_entry/pi_tree_entry),
 * NOT the 6.6 rb_node layout -> compact_waiter = 1.
 */

OFFSETS_ENTRY(
    "5.10.149-android12-9-00001-gda3d81545d1d-ab9545656",
    STRUCT_OFFSETS_5_10,
    .kernel_phys_load = 0xa8000000,
    /* pselect fd_set->waiter shift, DISASSEMBLY-DERIVED for the stock
     * 5.10 kernel: frames pselect_wrapper=0xa0 core_sys_select=0x1c0
     * futex_wrapper=0x90 do_futex=0x70 futex_wait_requeue_pi=0x1a0,
     * fd_set buffer=0x50 waiter local=0x90 -> raw shift 0, ghostlock
     * shift 0-2=-2. W1 (SELinux permissive + Write 1) verified on the
     * stock kernel with this value. GHOSTLOCK_SHIFT env overrides. */
    .pselect_waiter_shift = -2,
    .off_init_task = 0x278bf80,
    .off_init_cred = 0x27a0930,
    .off_root_task_group = 0x2980040,
    .off_selinux_enforcing = 0x2a2fb98,
    .off_selinux_blob_sizes = 0x22e05f0,
    .off_security_hook_heads = 0x22dff60,
    .off_slide_nfulnl_logger = 0x2781450,
    .off_slide_loggers_0_1 = 0x2781388,
    .off_slide_boot_id = 0x2a4933d,
),

/* BTF reference (5.10 GKI arm64, verified against device kallsyms): */
/* rt_mutex_waiter: tree_entry=0x00 pi_tree_entry=0x18 task=0x30 lock=0x38 prio=0x40 deadline=0x48 (size 0x50) */
/* cred: uid=0x04 gid=0x08 securebits=0x24 security=0x78 (size 0xa8) */
/* mm_struct: size 0x3e0 (SLUB stride; BTF reports 0x3e0) */
/* seccomp: mode=0x00 filter_count=0x04 filter=0x08 (size 0x10) */
