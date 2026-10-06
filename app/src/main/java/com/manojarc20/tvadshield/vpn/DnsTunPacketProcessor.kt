package com.manojarc20.tvadshield.dns

sealed interface TunPacketResult {
    data class Response(val packet: ByteArray) : TunPacketResult
    data object Unsupported : TunPacketResult
    data object Malformed : TunPacketResult
}

/**
 * Pure packet-to-policy bridge for IPv4/IPv6 UDP DNS datagrams. Non-DNS traffic is returned as
 * Unsupported; callers must not silently drop it. This bridge is not wired to a TUN descriptor
 * because full dual-stack traffic forwarding is not implemented.
 */
class DnsTunPacketProcessor(private val dnsProcessor: DnsPacketProcessor) {
    fun process(packet: ByteArray): TunPacketResult {
        return when (val parsed = UdpIpPacketCodec.parse(packet)) {
            IpPacketParseResult.Malformed -> TunPacketResult.Malformed
            IpPacketParseResult.Unsupported -> TunPacketResult.Unsupported
            is IpPacketParseResult.Udp -> {
                val datagram = parsed.packet
                if (datagram.destinationPort != DNS_PORT) {
                    TunPacketResult.Unsupported
                } else {
                    val response = dnsProcessor.process(datagram.payload)
                        ?: return TunPacketResult.Malformed
                    TunPacketResult.Response(UdpIpPacketCodec.responseTo(datagram, response))
                }
            }
        }
    }

    private companion object {
        const val DNS_PORT = 53
    }
}
