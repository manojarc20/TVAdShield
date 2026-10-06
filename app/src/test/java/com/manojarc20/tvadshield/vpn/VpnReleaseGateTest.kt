package com.manojarc20.tvadshield.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnReleaseGateTest {
    private val fullyReady = VpnForwardingReadiness(
        ipv4Tcp = true,
        ipv4Udp = true,
        ipv6Tcp = true,
        ipv6Udp = true,
        quicIpv4 = true,
        quicIpv6 = true,
        udpDnsIpv4 = true,
        tcpDnsIpv4 = true,
        udpDnsIpv6 = true,
        tcpDnsIpv6 = true,
        dnsFiltering = true,
        noDnsBypass = true,
        protectedEgress = true,
        returnTraffic = true,
        boundedFlowState = true,
        icmpFailureBehaviorValidated = true,
        lifecycleCleanup = true,
        emergencyStop = true,
        automatedTests = true
    )

    @Test
    fun currentBuildCannotEstablishVpn() {
        assertFalse(VpnReleaseGate.mayEstablishVpn())
    }

    @Test
    fun everyNormalConnectivityAndSafetyRequirementMustBeTrue() {
        assertTrue(VpnReleaseGate.mayEstablishVpn(fullyReady))

        val incompleteReadiness = listOf(
            fullyReady.copy(ipv4Tcp = false),
            fullyReady.copy(ipv4Udp = false),
            fullyReady.copy(ipv6Tcp = false),
            fullyReady.copy(ipv6Udp = false),
            fullyReady.copy(quicIpv4 = false),
            fullyReady.copy(quicIpv6 = false),
            fullyReady.copy(udpDnsIpv4 = false),
            fullyReady.copy(tcpDnsIpv4 = false),
            fullyReady.copy(udpDnsIpv6 = false),
            fullyReady.copy(tcpDnsIpv6 = false),
            fullyReady.copy(dnsFiltering = false),
            fullyReady.copy(noDnsBypass = false),
            fullyReady.copy(protectedEgress = false),
            fullyReady.copy(returnTraffic = false),
            fullyReady.copy(boundedFlowState = false),
            fullyReady.copy(icmpFailureBehaviorValidated = false),
            fullyReady.copy(lifecycleCleanup = false),
            fullyReady.copy(emergencyStop = false),
            fullyReady.copy(automatedTests = false)
        )

        incompleteReadiness.forEach { assertFalse(VpnReleaseGate.mayEstablishVpn(it)) }
    }

    @Test
    fun internetEchoForwardingIsNotAnIndependentReleaseRequirement() {
        // ICMP echo is diagnostic. Required ICMP error/MTU behavior is covered by
        // icmpFailureBehaviorValidated above.
        assertTrue(VpnReleaseGate.mayEstablishVpn(fullyReady))
    }
}
