package com.manojarc20.tvadshield.dns

/** Parsed UDP payload inside a complete IPv4 or IPv6 packet. */
data class UdpIpPacket(
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
    val ipv6: Boolean,
    val hopLimit: Int
)

sealed interface IpPacketParseResult {
    data class Udp(val packet: UdpIpPacket) : IpPacketParseResult
    data object Unsupported : IpPacketParseResult
    data object Malformed : IpPacketParseResult
}

/**
 * Bounds-checked IPv4/IPv6 UDP packet parser and response builder for unfragmented packets.
 * IPv6 extension headers (Hop-by-Hop, Routing, Destination Options, and atomic Fragment) are
 * walked with strict length limits. Non-UDP, fragmented, ESP, and unknown extension chains are
 * reported as unsupported. This codec is not connected to a VPN/TUN service.
 */
object UdpIpPacketCodec {
    fun parse(packet: ByteArray): IpPacketParseResult {
        if (packet.isEmpty()) return IpPacketParseResult.Malformed
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> parseIpv4(packet)
            6 -> parseIpv6(packet)
            else -> IpPacketParseResult.Unsupported
        }
    }

    fun responseTo(request: UdpIpPacket, payload: ByteArray): ByteArray =
        encode(
            UdpIpPacket(
                sourceAddress = request.destinationAddress,
                destinationAddress = request.sourceAddress,
                sourcePort = request.destinationPort,
                destinationPort = request.sourcePort,
                payload = payload,
                ipv6 = request.ipv6,
                hopLimit = request.hopLimit
            )
        )

    /** Encodes a complete UDP packet and calculates required IP/UDP checksums. */
    fun encode(datagram: UdpIpPacket): ByteArray {
        require(datagram.sourceAddress.size == datagram.destinationAddress.size)
        require(datagram.sourceAddress.size == if (datagram.ipv6) 16 else 4)
        require(datagram.sourcePort in 0..65535 && datagram.destinationPort in 0..65535)
        require(datagram.hopLimit in 1..255)
        return if (datagram.ipv6) encodeIpv6(datagram) else encodeIpv4(datagram)
    }

    private fun parseIpv4(packet: ByteArray): IpPacketParseResult {
        if (packet.size < IPV4_MIN_HEADER) return IpPacketParseResult.Malformed
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        val totalLength = u16(packet, 2)
        if (headerLength < IPV4_MIN_HEADER || headerLength > packet.size ||
            totalLength != packet.size || totalLength < headerLength + UDP_HEADER
        ) return IpPacketParseResult.Malformed
        if (checksum(packet, 0, headerLength) != 0xffff) return IpPacketParseResult.Malformed

        val fragmentField = u16(packet, 6)
        if (fragmentField and IPV4_FRAGMENT_MASK != 0) return IpPacketParseResult.Unsupported
        if ((packet[9].toInt() and 0xff) != IP_PROTOCOL_UDP) return IpPacketParseResult.Unsupported

        val udpOffset = headerLength
        val udpLength = u16(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER || udpOffset + udpLength != totalLength) {
            return IpPacketParseResult.Malformed
        }
        val checksumField = u16(packet, udpOffset + 6)
        if (checksumField != 0 && udpChecksumIpv4(packet, udpOffset, udpLength) != 0xffff) {
            return IpPacketParseResult.Malformed
        }

        return IpPacketParseResult.Udp(
            UdpIpPacket(
                packet.copyOfRange(12, 16),
                packet.copyOfRange(16, 20),
                u16(packet, udpOffset),
                u16(packet, udpOffset + 2),
                packet.copyOfRange(udpOffset + UDP_HEADER, totalLength),
                ipv6 = false,
                hopLimit = packet[8].toInt() and 0xff
            )
        )
    }

    private fun parseIpv6(packet: ByteArray): IpPacketParseResult {
        if (packet.size < IPV6_HEADER) return IpPacketParseResult.Malformed
        val payloadLength = u16(packet, 4)
        if (payloadLength == 0 || packet.size != IPV6_HEADER + payloadLength) {
            return IpPacketParseResult.Malformed
        }

        var nextHeader = packet[6].toInt() and 0xff
        var offset = IPV6_HEADER
        val end = packet.size
        var extensions = 0

        while (nextHeader != IP_PROTOCOL_UDP) {
            if (++extensions > MAX_IPV6_EXTENSIONS) return IpPacketParseResult.Unsupported
            when (nextHeader) {
                IPV6_HOP_BY_HOP, IPV6_ROUTING, IPV6_DESTINATION -> {
                    if (offset + 2 > end) return IpPacketParseResult.Malformed
                    val following = packet[offset].toInt() and 0xff
                    val extensionLength = ((packet[offset + 1].toInt() and 0xff) + 1) * 8
                    if (offset + extensionLength > end) return IpPacketParseResult.Malformed
                    nextHeader = following
                    offset += extensionLength
                }
                IPV6_FRAGMENT -> {
                    if (offset + 8 > end) return IpPacketParseResult.Malformed
                    val following = packet[offset].toInt() and 0xff
                    val fragment = u16(packet, offset + 2)
                    if (fragment and IPV6_FRAGMENT_MASK != 0 || packet[offset + 3].toInt() and 1 != 0) {
                        return IpPacketParseResult.Unsupported
                    }
                    nextHeader = following
                    offset += 8
                }
                IPV6_AH -> {
                    if (offset + 2 > end) return IpPacketParseResult.Malformed
                    val following = packet[offset].toInt() and 0xff
                    val extensionLength = ((packet[offset + 1].toInt() and 0xff) + 2) * 4
                    if (offset + extensionLength > end) return IpPacketParseResult.Malformed
                    nextHeader = following
                    offset += extensionLength
                }
                else -> return IpPacketParseResult.Unsupported
            }
        }

        if (offset + UDP_HEADER > end) return IpPacketParseResult.Malformed
        val udpLength = u16(packet, offset + 4)
        if (udpLength < UDP_HEADER || offset + udpLength != end) return IpPacketParseResult.Malformed
        if (u16(packet, offset + 6) == 0 ||
            udpChecksumIpv6(packet, offset, udpLength) != 0xffff
        ) return IpPacketParseResult.Malformed

        return IpPacketParseResult.Udp(
            UdpIpPacket(
                packet.copyOfRange(8, 24),
                packet.copyOfRange(24, 40),
                u16(packet, offset),
                u16(packet, offset + 2),
                packet.copyOfRange(offset + UDP_HEADER, end),
                ipv6 = true,
                hopLimit = packet[7].toInt() and 0xff
            )
        )
    }

    private fun encodeIpv4(datagram: UdpIpPacket): ByteArray {
        val udpLength = UDP_HEADER + datagram.payload.size
        val totalLength = IPV4_MIN_HEADER + udpLength
        require(totalLength <= 65_535)
        val packet = ByteArray(totalLength)
        packet[0] = 0x45
        packet[1] = 0
        putU16(packet, 2, totalLength)
        putU16(packet, 4, 0)
        putU16(packet, 6, IPV4_DONT_FRAGMENT)
        packet[8] = datagram.hopLimit.toByte()
        packet[9] = IP_PROTOCOL_UDP.toByte()
        datagram.sourceAddress.copyInto(packet, 12)
        datagram.destinationAddress.copyInto(packet, 16)
        putU16(packet, 10, checksum(packet, 0, IPV4_MIN_HEADER))

        val offset = IPV4_MIN_HEADER
        putU16(packet, offset, datagram.sourcePort)
        putU16(packet, offset + 2, datagram.destinationPort)
        putU16(packet, offset + 4, udpLength)
        datagram.payload.copyInto(packet, offset + UDP_HEADER)
        val udpChecksum = checksumIpv4Udp(packet, offset, udpLength)
        putU16(packet, offset + 6, if (udpChecksum == 0) 0xffff else udpChecksum)
        return packet
    }

    private fun encodeIpv6(datagram: UdpIpPacket): ByteArray {
        val udpLength = UDP_HEADER + datagram.payload.size
        require(udpLength <= 65_535)
        val packet = ByteArray(IPV6_HEADER + udpLength)
        packet[0] = 0x60
        putU16(packet, 4, udpLength)
        packet[6] = IP_PROTOCOL_UDP.toByte()
        packet[7] = datagram.hopLimit.toByte()
        datagram.sourceAddress.copyInto(packet, 8)
        datagram.destinationAddress.copyInto(packet, 24)

        val offset = IPV6_HEADER
        putU16(packet, offset, datagram.sourcePort)
        putU16(packet, offset + 2, datagram.destinationPort)
        putU16(packet, offset + 4, udpLength)
        datagram.payload.copyInto(packet, offset + UDP_HEADER)
        putU16(packet, offset + 6, checksumIpv6Udp(packet, offset, udpLength))
        return packet
    }

    private fun udpChecksumIpv4(packet: ByteArray, offset: Int, length: Int): Int =
        checksumIpv4Udp(packet, offset, length, verifyExisting = true)

    private fun checksumIpv4Udp(packet: ByteArray, offset: Int, length: Int, verifyExisting: Boolean = false): Int {
        var sum = 0L
        sum += sumWords(packet, 12, 8)
        sum += IP_PROTOCOL_UDP.toLong()
        sum += length.toLong()
        sum += sumWords(packet, offset, length, checksumOffset = if (verifyExisting) -1 else offset + 6)
        return finishChecksum(sum)
    }

    private fun udpChecksumIpv6(packet: ByteArray, offset: Int, length: Int): Int =
        checksumIpv6Udp(packet, offset, length, verifyExisting = true)

    private fun checksumIpv6Udp(packet: ByteArray, offset: Int, length: Int, verifyExisting: Boolean = false): Int {
        var sum = 0L
        sum += sumWords(packet, 8, 32)
        sum += ((length ushr 16) and 0xffff).toLong()
        sum += (length and 0xffff).toLong()
        sum += IP_PROTOCOL_UDP.toLong()
        sum += sumWords(packet, offset, length, checksumOffset = if (verifyExisting) -1 else offset + 6)
        return finishChecksum(sum)
    }

    private fun checksum(bytes: ByteArray, offset: Int, length: Int): Int =
        finishChecksum(sumWords(bytes, offset, length))

    private fun sumWords(bytes: ByteArray, offset: Int, length: Int, checksumOffset: Int = -1): Long {
        var sum = 0L
        var index = 0
        while (index < length) {
            val absolute = offset + index
            val high = if (absolute == checksumOffset) 0 else bytes[absolute].toInt() and 0xff
            val low = if (index + 1 == length) 0 else if (absolute + 1 == checksumOffset) 0
                else bytes[absolute + 1].toInt() and 0xff
            sum += (high shl 8 or low).toLong()
            index += 2
        }
        return sum
    }

    private fun finishChecksum(initial: Long): Int {
        var sum = initial
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private const val IPV4_MIN_HEADER = 20
    private const val IPV6_HEADER = 40
    private const val UDP_HEADER = 8
    private const val IP_PROTOCOL_UDP = 17
    private const val IPV4_FRAGMENT_MASK = 0x3fff
    private const val IPV4_DONT_FRAGMENT = 0x4000
    private const val IPV6_HOP_BY_HOP = 0
    private const val IPV6_ROUTING = 43
    private const val IPV6_FRAGMENT = 44
    private const val IPV6_AH = 51
    private const val IPV6_DESTINATION = 60
    private const val IPV6_FRAGMENT_MASK = 0xfff8
    private const val MAX_IPV6_EXTENSIONS = 8
}
