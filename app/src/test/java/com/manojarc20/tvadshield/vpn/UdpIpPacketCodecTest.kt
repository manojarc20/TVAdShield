package com.manojarc20.tvadshield.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UdpIpPacketCodecTest {
    @Test
    fun parsesAndRebuildsIpv4UdpPacket() {
        val original = datagram(ipv6 = false)
        val parsed = UdpIpPacketCodec.parse(UdpIpPacketCodec.encode(original)) as IpPacketParseResult.Udp
        assertArrayEquals(original.payload, parsed.packet.payload)
        assertArrayEquals(original.sourceAddress, parsed.packet.sourceAddress)
        assertEquals(53, parsed.packet.destinationPort)

        val reply = UdpIpPacketCodec.responseTo(parsed.packet, byteArrayOf(4, 5))
        val decodedReply = (UdpIpPacketCodec.parse(reply) as IpPacketParseResult.Udp).packet
        assertArrayEquals(original.destinationAddress, decodedReply.sourceAddress)
        assertArrayEquals(original.sourceAddress, decodedReply.destinationAddress)
        assertEquals(original.sourcePort, decodedReply.destinationPort)
    }

    @Test
    fun parsesAndRebuildsIpv6UdpPacketWithMandatoryChecksum() {
        val original = datagram(ipv6 = true)
        val packet = UdpIpPacketCodec.encode(original)
        val parsed = UdpIpPacketCodec.parse(packet) as IpPacketParseResult.Udp
        assertTrue(parsed.packet.ipv6)
        assertArrayEquals(original.payload, parsed.packet.payload)
        assertArrayEquals(original.sourceAddress, parsed.packet.sourceAddress)
        val reply = UdpIpPacketCodec.responseTo(parsed.packet, byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), (UdpIpPacketCodec.parse(reply) as IpPacketParseResult.Udp).packet.payload)
    }

    @Test
    fun rejectsTruncatedPacketAndUnsupportedProtocol() {
        assertEquals(IpPacketParseResult.Malformed, UdpIpPacketCodec.parse(byteArrayOf(0x45)))
        val udp = UdpIpPacketCodec.encode(datagram(ipv6 = false))
        udp[9] = 6
        udp[10] = 0
        udp[11] = 0
        val headerSum = (0 until 20 step 2).sumOf { index ->
            ((udp[index].toInt() and 0xff) shl 8) or (udp[index + 1].toInt() and 0xff)
        }
        val folded = (headerSum and 0xffff) + (headerSum ushr 16)
        val checksum = folded.inv() and 0xffff
        udp[10] = (checksum ushr 8).toByte()
        udp[11] = checksum.toByte()
        assertEquals(IpPacketParseResult.Unsupported, UdpIpPacketCodec.parse(udp))
    }

    @Test
    fun rejectsInvalidIpv4HeaderChecksum() {
        val packet = UdpIpPacketCodec.encode(datagram(ipv6 = false))
        packet[8] = 32
        assertEquals(IpPacketParseResult.Malformed, UdpIpPacketCodec.parse(packet))
    }

    @Test
    fun unsupportedIpv6ProtocolDoesNotPretendToParseDns() {
        val packet = UdpIpPacketCodec.encode(datagram(ipv6 = true))
        packet[6] = 6
        assertEquals(IpPacketParseResult.Unsupported, UdpIpPacketCodec.parse(packet))
    }

    private fun datagram(ipv6: Boolean): UdpIpPacket =
        UdpIpPacket(
            sourceAddress = if (ipv6) ByteArray(16) { (it + 1).toByte() } else byteArrayOf(192.toByte(), 0, 2, 9),
            destinationAddress = if (ipv6) ByteArray(16) { (it + 17).toByte() } else byteArrayOf(10, 1, 0, 2),
            sourcePort = 53000,
            destinationPort = 53,
            payload = byteArrayOf(1, 2, 3, 4, 5),
            ipv6 = ipv6,
            hopLimit = 64
        )
}
