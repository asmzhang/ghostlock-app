package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Ordering rules for picking the manager that supplies `ksud`. Pure logic, so
 * no Robolectric: the device-dependent part is [ManagerScanner.scan].
 */
class ManagerScannerTest {
    private fun candidate(
        packageName: String,
        hasKsud: Boolean = true,
    ) = ManagerScanner.Candidate(
        packageName = packageName,
        label = packageName.substringAfterLast('.'),
        hasKsud = hasKsud,
        builtin = packageName in ManagerScanner.BUILTIN,
    )

    @Test
    fun `builtin priority wins over list order`() {
        val picked = ManagerScanner.pick(
            listOf(
                candidate("com.kowx712.supermanager"),
                candidate("me.weishu.kernelsu"),
            ),
        )
        assertEquals("me.weishu.kernelsu", picked?.packageName)
    }

    @Test
    fun `a manager without ksud is skipped even when it outranks`() {
        val picked = ManagerScanner.pick(
            listOf(
                candidate("me.weishu.kernelsu.pr", hasKsud = false),
                candidate("com.resukisu.resukisu"),
            ),
        )
        assertEquals("com.resukisu.resukisu", picked?.packageName)
    }

    @Test
    fun `bakasu is discoverable and ranks after resukisu`() {
        val picked = ManagerScanner.pick(
            listOf(
                candidate("org.bakasu.bakasu"),
                candidate("com.resukisu.resukisu"),
            ),
        )
        assertEquals("com.resukisu.resukisu", picked?.packageName)
    }

    @Test
    fun `no installed manager yields null`() {
        assertNull(ManagerScanner.pick(emptyList()))
    }

    @Test
    fun `no manager shipping ksud yields null`() {
        assertNull(ManagerScanner.pick(listOf(candidate("me.weishu.kernelsu", hasKsud = false))))
    }

    @Test
    fun `describe names the packages and flags the ones without ksud`() {
        val text = ManagerScanner.describe(
            listOf(
                candidate("me.weishu.kernelsu", hasKsud = false),
                candidate("org.bakasu.bakasu"),
            ),
        )
        assertEquals("me.weishu.kernelsu (no ksud), org.bakasu.bakasu", text)
    }
}
