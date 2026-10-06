package com.manojarc20.tvadshield.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnReleaseGateTest {
    @Test
    fun currentBuildCannotEstablishVpn() {
        assertFalse(VpnReleaseGate.mayEstablishVpn())
    }

    @Test
    fun everyAddressFamilyAndTrafficClassMustBeImplementedAndTested() {
        assertFalse(VpnReleaseGate.mayEstablishVpn(true, false, true))
        assertFalse(VpnReleaseGate.mayEstablishVpn(false, true, true))
        assertFalse(VpnReleaseGate.mayEstablishVpn(true, true, false))
        assertTrue(VpnReleaseGate.mayEstablishVpn(true, true, true))
    }
}
