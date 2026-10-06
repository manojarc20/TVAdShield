package com.manojarc20.tvadshield.vpn

/**
 * Evidence gate for creating a VPN interface. It covers application traffic and safety properties
 * required for normal operation; Internet ICMP echo is diagnostic and is not a gate requirement.
 */
data class VpnForwardingReadiness(
    val ipv4Tcp: Boolean = false,
    val ipv4Udp: Boolean = false,
    val ipv6Tcp: Boolean = false,
    val ipv6Udp: Boolean = false,
    val quicIpv4: Boolean = false,
    val quicIpv6: Boolean = false,
    val udpDnsIpv4: Boolean = false,
    val tcpDnsIpv4: Boolean = false,
    val udpDnsIpv6: Boolean = false,
    val tcpDnsIpv6: Boolean = false,
    val dnsFiltering: Boolean = false,
    val noDnsBypass: Boolean = false,
    val protectedEgress: Boolean = false,
    val returnTraffic: Boolean = false,
    val boundedFlowState: Boolean = false,
    val icmpFailureBehaviorValidated: Boolean = false,
    val lifecycleCleanup: Boolean = false,
    val emergencyStop: Boolean = false,
    val automatedTests: Boolean = false
) {
    fun isComplete(): Boolean =
        ipv4Tcp && ipv4Udp && ipv6Tcp && ipv6Udp &&
            quicIpv4 && quicIpv6 &&
            udpDnsIpv4 && tcpDnsIpv4 && udpDnsIpv6 && tcpDnsIpv6 &&
            dnsFiltering && noDnsBypass && protectedEgress && returnTraffic &&
            boundedFlowState && icmpFailureBehaviorValidated &&
            lifecycleCleanup && emergencyStop && automatedTests

    companion object {
        /** All requirements remain false until independently implemented and tested. */
        val CURRENT = VpnForwardingReadiness()
    }
}

/** Closed until every required forwarding capability and safety property is proven. */
object VpnReleaseGate {
    fun mayEstablishVpn(): Boolean = mayEstablishVpn(VpnForwardingReadiness.CURRENT)

    internal fun mayEstablishVpn(readiness: VpnForwardingReadiness): Boolean =
        readiness.isComplete()
}
