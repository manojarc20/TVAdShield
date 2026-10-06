package com.manojarc20.tvadshield.vpn

/**
 * Evidence gate for creating any VPN interface. Every traffic class and lifecycle guarantee must
 * be implemented and tested; a partial tunnel is not safe to start.
 */
data class VpnForwardingReadiness(
    val ipv4Tcp: Boolean = false,
    val ipv4Udp: Boolean = false,
    val ipv4Icmp: Boolean = false,
    val ipv6Tcp: Boolean = false,
    val ipv6Udp: Boolean = false,
    val ipv6Icmpv6: Boolean = false,
    val dnsInterceptsIpv4: Boolean = false,
    val dnsInterceptsIpv6: Boolean = false,
    val returnTraffic: Boolean = false,
    val boundedFlowState: Boolean = false,
    val lifecycleCleanup: Boolean = false,
    val emergencyStop: Boolean = false,
    val automatedTests: Boolean = false,
    val preventsIpv6Bypass: Boolean = false
) {
    fun isComplete(): Boolean =
        ipv4Tcp && ipv4Udp && ipv4Icmp &&
            ipv6Tcp && ipv6Udp && ipv6Icmpv6 &&
            dnsInterceptsIpv4 && dnsInterceptsIpv6 &&
            returnTraffic && boundedFlowState && lifecycleCleanup &&
            emergencyStop && automatedTests && preventsIpv6Bypass

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
