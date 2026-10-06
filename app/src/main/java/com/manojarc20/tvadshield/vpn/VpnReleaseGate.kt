package com.manojarc20.tvadshield.vpn

/**
 * Release gate for creating any VPN interface. All families and traffic classes must be fully
 * forwarded and tested first. This build deliberately keeps the gate closed.
 */
object VpnReleaseGate {
    const val IPV4_FORWARDING_IMPLEMENTED_AND_TESTED = false
    const val IPV6_FORWARDING_IMPLEMENTED_AND_TESTED = false
    const val NON_DNS_FORWARDING_IMPLEMENTED_AND_TESTED = false

    fun mayEstablishVpn(): Boolean = mayEstablishVpn(
        ipv4ForwardingImplementedAndTested = IPV4_FORWARDING_IMPLEMENTED_AND_TESTED,
        ipv6ForwardingImplementedAndTested = IPV6_FORWARDING_IMPLEMENTED_AND_TESTED,
        nonDnsForwardingImplementedAndTested = NON_DNS_FORWARDING_IMPLEMENTED_AND_TESTED
    )

    internal fun mayEstablishVpn(
        ipv4ForwardingImplementedAndTested: Boolean,
        ipv6ForwardingImplementedAndTested: Boolean,
        nonDnsForwardingImplementedAndTested: Boolean
    ): Boolean =
        ipv4ForwardingImplementedAndTested &&
            ipv6ForwardingImplementedAndTested &&
            nonDnsForwardingImplementedAndTested
}
