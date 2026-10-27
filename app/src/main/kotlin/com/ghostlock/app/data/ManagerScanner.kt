package com.ghostlock.app.data

import android.content.pm.PackageManager
import java.io.File

/**
 * Finds the KernelSU-family manager that should supply `ksud`.
 *
 * Several managers ship the same `libksud.so` name (KernelSU, its `pr` build,
 * ReSukiSU, BakaSU, SuperManager). Copying "the first one that exists" picks the
 * wrong binary whenever a user has more than one installed, and the resulting
 * failure is silent: the script runs a `ksud` that does not match the manager
 * actually driving the kernel.
 *
 * Discovery is limited to [BUILTIN] on purpose. The manifest declares those
 * packages under `<queries>` instead of requesting QUERY_ALL_PACKAGES, so a
 * blanket `getInstalledPackages` scan would only ever see the same set while
 * asking for a permission the app does not need. A manager that is not listed
 * here has to be added to both this list and the manifest.
 */
internal object ManagerScanner {
    /** KernelSU-family managers, priority order. Keep in sync with the manifest. */
    val BUILTIN: List<String> = listOf(
        "me.weishu.kernelsu.pr",
        "me.weishu.kernelsu",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
        "com.kowx712.supermanager",
    )

    data class Candidate(
        val packageName: String,
        val label: String,
        val hasKsud: Boolean,
        val builtin: Boolean,
    )

    /**
     * Installed managers among [packages], in priority order. [packages] defaults
     * to [BUILTIN] and exists so tests can drive the ordering without a device.
     */
    fun scan(
        pm: PackageManager,
        selfPackage: String,
        packages: List<String> = BUILTIN,
    ): List<Candidate> = packages.mapNotNull { packageName ->
        if (packageName == selfPackage) return@mapNotNull null
        val info = runCatching { pm.getApplicationInfo(packageName, 0) }.getOrNull()
            ?: return@mapNotNull null
        Candidate(
            packageName = packageName,
            label = runCatching { pm.getApplicationLabel(info).toString() }
                .getOrDefault(packageName),
            hasKsud = File(info.nativeLibraryDir, KsudLibraryName).isFile,
            builtin = packageName in BUILTIN,
        )
    }

    /**
     * The manager to take `ksud` from: first installed candidate that actually
     * ships the binary, builtin order preserved. Pure, so the ordering rules are
     * testable off-device.
     */
    fun pick(candidates: List<Candidate>): Candidate? =
        candidates.filter { it.hasKsud }.minByOrNull { it.orderKey() }

    /** Diagnostics for the log when [pick] returns null. */
    fun describe(candidates: List<Candidate>): String = when {
        candidates.isEmpty() -> "no KernelSU-family manager installed"
        else -> candidates.joinToString { "${it.packageName}${if (it.hasKsud) "" else " (no ksud)"}" }
    }

    private fun Candidate.orderKey(): Int {
        val index = BUILTIN.indexOf(packageName)
        return if (index >= 0) index else BUILTIN.size
    }

    const val KsudLibraryName = "libksud.so"
}
