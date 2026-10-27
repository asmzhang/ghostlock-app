package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KernelPatchKmiTest {
    private val bundled = setOf(
        "android12-5.10",
        "android13-5.10",
        "android13-5.15",
        "android14-5.15",
        "android14-6.1",
        "android15-6.6",
        "android16-6.12",
    )

    @Test
    fun marbleReleaseUsesTheAndroid12Branch() {
        assertEquals(
            "android12-5.10",
            kernelPatchKmi("5.10.149-android12-9-00001-gda3d81545d1d-ab9545656", 32, bundled),
        )
    }

    @Test
    fun pixel6ReleaseUsesTheAndroid13BranchOfTheSameMinor() {
        assertEquals(
            "android13-5.10",
            kernelPatchKmi("5.10.157-android13-4-00001-g5c7ff5dc7aac-ab10381520", 33, bundled),
        )
    }

    @Test
    fun releaseMarkerWinsOverTheRunningSdk() {
        assertEquals("android12-5.10", kernelPatchKmi("5.10.198-android12-9-00001-g1a2b3c", 33, bundled))
    }

    @Test
    fun vendorKernelWithoutMarkerFallsBackToTheNewestBranchAtOrBelowTheSdk() {
        assertEquals("android13-5.10", kernelPatchKmi("5.10.198-g1a2b3c", 33, bundled))
        assertEquals("android14-6.1", kernelPatchKmi("6.1.145-g1a2b3c", 35, bundled))
        assertEquals("android12-5.10", kernelPatchKmi("5.10.198-g1a2b3c", 30, bundled))
    }

    @Test
    fun unknownOrUnparseableKernelHasNoModule() {
        assertNull(kernelPatchKmi("4.14.186-perf+", 30, bundled))
        assertNull(kernelPatchKmi("garbage", 33, bundled))
        assertNull(kernelPatchKmi("7.0.1-g1a2b3c", 36, bundled))
    }
}
