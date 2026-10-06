package com.manojarc20.tvadshield.dns

import com.manojarc20.tvadshield.filter.RuleEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsTunPacketProcessorTest {
    @Test
    fun reconstructsIpv4DnsResponseWithoutChangingDnsTransaction() {
        val dnsQuery = query("ads.example.com", 1)
        val processor = DnsTunPacketProcessor(
            DnsPacketProcessor(RuleEngine(emptyList()), DnsWireResolver { _, _ -> error("unused") })
        )
        val result = processor.process(
            UdpIpPacketCodec.encode(packet(ipv6 = false, dnsPayload = dnsQuery))
        ) as TunPacketResult.Response
        val response = (UdpIpPacketCodec.parse(result.packet) as IpPacketParseResult.Udp).packet
        assertEquals(53, response.sourcePort)
        assertEquals(53_000, response.destinationPort)
        assertEquals(0x1234, ((response.payload[0].toInt() and 0xff) shl 8) or (response.payload[1].toInt() and 0xff))
    }

    @Test
    fun reconstructsIpv6DnsResponse() {
        val processor = DnsTunPacketProcessor(
            DnsPacketProcessor(RuleEngine(emptyList()), DnsWireResolver { query, _ ->
                val question = (DnsWireCodec.parseQuery(query) as DnsQueryParseResult.Valid).question
                DnsWireCodec.responseFor(question, DnsRcode.NOERROR)
            })
        )
        val result = processor.process(
            UdpIpPacketCodec.encode(packet(ipv6 = true, dnsPayload = query("ipv6.example.com", 28)))
        )
        assertTrue(result is TunPacketResult.Response)
    }

    @Test
    fun refusesToSilentlyHandleNonDnsTraffic() {
        val processor = DnsTunPacketProcessor(
            DnsPacketProcessor(RuleEngine(emptyList()), DnsWireResolver { _, _ -> byteArrayOf() })
        )
        val nonDns = packet(ipv6 = false, dnsPayload = byteArrayOf(1, 2)).copy(destinationPort = 443)
        assertEquals(
            TunPacketResult.Unsupported,
            processor.process(UdpIpPacketCodec.encode(nonDns))
        )
    }

    private fun packet(ipv6: Boolean, dnsPayload: ByteArray) = UdpIpPacket(
        sourceAddress = if (ipv6) ByteArray(16) { it.toByte() } else byteArrayOf(192.toByte(), 0, 2, 1),
        destinationAddress = if (ipv6) ByteArray(16) { (it + 32).toByte() } else byteArrayOf(10, 111, 0, 2),
        sourcePort = 53_000,
        destinationPort = 53,
        payload = dnsPayload,
        ipv6 = ipv6,
        hopLimit = 64
    )

    private fun query(host: String, type: Int): ByteArray {
        val qname = host.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() }
            .toByteArray() + byteArrayOf(0)
        return ByteArray(12 + qname.size + 4).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 1
            it[5] = 1
            qname.copyInto(it, 12)
            val offset = 12 + qname.size
            it[offset] = (type ushr 8).toByte()
            it[offset + 1] = type.toByte()
            it[offset + 3] = 1
        }
    }
}
