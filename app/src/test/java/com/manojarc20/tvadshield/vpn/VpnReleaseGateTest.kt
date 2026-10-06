package com.manojarc20.tvadshield.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnReleaseGateTest {
    private val fullyReady = VpnForwardingReadiness(
        ipv4Tcp = true,
        ipv4Udp = true,
        ipv4Icmp = true,
        ipv6Tcp = true,
        ipv6Udp = true,
        ipv6Icmpv6 = true,
        dnsInterceptsIpv4 = true,
        dnsInterceptsIpv6 = true,
        returnTraffic = true,
        boundedFlowState = true,
        lifecycleCleanup = true,
        emergencyStop = true,
        automatedTests = true,
        preventsIpv6Bypass = true
    )

    @Test
    fun currentBuildCannotEstablishVpn() {
        assertFalse(VpnReleaseGate.mayEstablishVpn())
    }

    @Test
    fun allReadinessRequirementsMustBeTrue() {
        assertTrue(VpnReleaseGate.mayEstablishVpn(fullyReady))

        val incompleteReadiness = listOf(
            fullyReady.copy(ipv4Tcp = false),
            fullyReady.copy(ipv4Udp = false),
            fullyReady.copy(ipv4Icmp = false),
            fullyReady.copy(ipv6Tcp = false),
            fullyReady.copy(ipv6Udp = false),
            fullyReady.copy(ipv6Icmpv6 = false),
            fullyReady.copy(dnsInterceptsIpv4 = false),
            fullyReady.copy(dnsInterceptsIpv6 = false),
            fullyReady.copy(returnTraffic = false),
            fullyReady.copy(boundedFlowState = false),
            fullyReady.copy(lifecycleCleanup = false),
            fullyReady.copy(emergencyStop = false),
            fullyReady.copy(automatedTests = false),
            fullyReady.copy(preventsIpv6Bypass = false)
        )

        incompleteReadiness.forEach { assertFalse(VpnReleaseGate.mayEstablishVpn(it)) }
    }
}
