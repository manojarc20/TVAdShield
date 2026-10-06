package com.manojarc20.tvadshield.dns

import com.manojarc20.tvadshield.filter.HostnameNormalizer

/** Parsed single-question DNS query. Byte arrays are copied at the API boundary. */
data class DnsQuestion(
    val transactionId: Int,
    val flags: Int,
    val hostname: String,
    val queryType: Int,
    val queryClass: Int,
    val encodedQuestion: ByteArray,
    val originalPacket: ByteArray
)

object DnsRcode {
    const val NOERROR = 0
    const val FORMERR = 1
    const val SERVFAIL = 2
    const val NXDOMAIN = 3
    const val NOTIMP = 4
}

sealed interface DnsQueryParseResult {
    data class Valid(val question: DnsQuestion) : DnsQueryParseResult
    data class Malformed(val transactionId: Int?) : DnsQueryParseResult
}

/** Bounds-checked DNS message helpers for UDP DNS, including compression-pointer and RR bounds checks. */
object DnsWireCodec {
    fun parseQuery(packet: ByteArray): DnsQueryParseResult {
        val id = if (packet.size >= 2) u16(packet, 0) else null
        if (packet.size < HEADER_SIZE || packet.size > MAX_MESSAGE_SIZE) {
            return DnsQueryParseResult.Malformed(id)
        }

        val flags = u16(packet, 2)
        if (flags and FLAG_QR != 0 || flags and OPCODE_MASK != 0) {
            return DnsQueryParseResult.Malformed(id)
        }
        if (u16(packet, 4) != 1 || u16(packet, 6) != 0 || u16(packet, 8) != 0) {
            return DnsQueryParseResult.Malformed(id)
        }

        return try {
            val name = readName(packet, HEADER_SIZE)
            val normalized = HostnameNormalizer.normalize(name.value)
                ?: return DnsQueryParseResult.Malformed(id)
            var offset = name.nextOffset
            require(offset + 4 <= packet.size)
            val queryType = u16(packet, offset)
            val queryClass = u16(packet, offset + 2)
            offset += 4

            repeat(u16(packet, 10)) {
                offset = skipResourceRecord(packet, offset)
            }
            require(offset == packet.size)

            DnsQueryParseResult.Valid(
                DnsQuestion(
                    transactionId = id!!,
                    flags = flags,
                    hostname = normalized,
                    queryType = queryType,
                    queryClass = queryClass,
                    encodedQuestion = packet.copyOfRange(HEADER_SIZE, name.nextOffset + 4),
                    originalPacket = packet.copyOf()
                )
            )
        } catch (_: IllegalArgumentException) {
            DnsQueryParseResult.Malformed(id)
        } catch (_: IndexOutOfBoundsException) {
            DnsQueryParseResult.Malformed(id)
        }
    }

    fun isValidResponse(packet: ByteArray, expected: DnsQuestion): Boolean {
        if (packet.size < HEADER_SIZE || packet.size > MAX_MESSAGE_SIZE) return false
        if (u16(packet, 0) != expected.transactionId) return false
        val flags = u16(packet, 2)
        if (flags and FLAG_QR == 0 || flags and OPCODE_MASK != 0 || u16(packet, 4) != 1) return false

        return try {
            val name = readName(packet, HEADER_SIZE)
            var offset = name.nextOffset
            require(offset + 4 <= packet.size)
            val type = u16(packet, offset)
            val qclass = u16(packet, offset + 2)
            offset += 4
            if (HostnameNormalizer.normalize(name.value) != expected.hostname ||
                type != expected.queryType || qclass != expected.queryClass
            ) return false

            val records = u16(packet, 6) + u16(packet, 8) + u16(packet, 10)
            repeat(records) { offset = skipResourceRecord(packet, offset) }
            offset == packet.size
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: IndexOutOfBoundsException) {
            false
        }
    }

    fun responseFor(question: DnsQuestion, rcode: Int): ByteArray {
        require(rcode in 0..15)
        val packet = ByteArray(HEADER_SIZE + question.encodedQuestion.size)
        putU16(packet, 0, question.transactionId)
        putU16(packet, 2, FLAG_QR or FLAG_RA or (question.flags and FLAG_RD) or rcode)
        putU16(packet, 4, 1)
        question.encodedQuestion.copyInto(packet, HEADER_SIZE)
        return packet
    }

    fun errorResponse(packet: ByteArray, rcode: Int): ByteArray? {
        if (packet.size < 2) return null
        val response = ByteArray(HEADER_SIZE)
        putU16(response, 0, u16(packet, 0))
        val flags = if (packet.size >= 4) u16(packet, 2) else 0
        putU16(response, 2, FLAG_QR or FLAG_RA or (flags and FLAG_RD) or rcode)
        return response
    }

    private data class NameRead(val value: String, val nextOffset: Int)

    private fun readName(packet: ByteArray, start: Int): NameRead {
        require(start < packet.size)
        val labels = ArrayList<String>()
        val visitedPointers = HashSet<Int>()
        var cursor = start
        var nextOffset = -1
        var jumped = false

        while (true) {
            require(cursor < packet.size)
            val length = packet[cursor].toInt() and 0xff
            if (length == 0) {
                if (!jumped) nextOffset = cursor + 1
                break
            }
            when (length and 0xc0) {
                0xc0 -> {
                    require(cursor + 1 < packet.size)
                    val pointer = ((length and 0x3f) shl 8) or (packet[cursor + 1].toInt() and 0xff)
                    require(pointer < packet.size && visitedPointers.add(pointer))
                    if (!jumped) nextOffset = cursor + 2
                    jumped = true
                    cursor = pointer
                }
                0x00 -> {
                    require(length <= 63 && cursor + 1 + length <= packet.size)
                    val bytes = packet.copyOfRange(cursor + 1, cursor + 1 + length)
                    require(bytes.all { (it.toInt() and 0xff) in 0x21..0x7e && it != '.'.code.toByte() })
                    labels += bytes.toString(Charsets.US_ASCII)
                    cursor += 1 + length
                }
                else -> throw IllegalArgumentException("Invalid DNS label encoding")
            }
            require(labels.size <= MAX_LABELS && visitedPointers.size <= MAX_POINTERS)
        }

        require(nextOffset >= 0)
        val value = labels.joinToString(".")
        require(value.length <= MAX_NAME_LENGTH)
        return NameRead(value, nextOffset)
    }

    private fun skipResourceRecord(packet: ByteArray, start: Int): Int {
        val name = readName(packet, start)
        var offset = name.nextOffset
        require(offset + 10 <= packet.size)
        val dataLength = u16(packet, offset + 8)
        offset += 10
        require(offset + dataLength <= packet.size)
        return offset + dataLength
    }

    private fun u16(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 2 <= bytes.size)
        return ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private const val HEADER_SIZE = 12
    private const val MAX_MESSAGE_SIZE = 65_535
    private const val MAX_NAME_LENGTH = 253
    private const val MAX_LABELS = 127
    private const val MAX_POINTERS = 32
    private const val FLAG_QR = 0x8000
    private const val FLAG_RD = 0x0100
    private const val FLAG_RA = 0x0080
    private const val OPCODE_MASK = 0x7800
}
