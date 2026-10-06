package com.manojarc20.tvadshield.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsWireCodecTest {
    @Test
    fun parsesAQueryAndPreservesTransactionId() {
        val query = query("www.example.com", 1, 0x1234)
        val parsed = DnsWireCodec.parseQuery(query) as DnsQueryParseResult.Valid
        assertEquals(0x1234, parsed.question.transactionId)
        assertEquals("www.example.com", parsed.question.hostname)
        assertEquals(1, parsed.question.queryType)
    }

    @Test
    fun parsesAaaaQuery() {
        val parsed = DnsWireCodec.parseQuery(query("www.example.com", 28)) as DnsQueryParseResult.Valid
        assertEquals(28, parsed.question.queryType)
    }

    @Test
    fun acceptsStructurallyValidEdnsOptRecord() {
        val base = query("example.com", 1)
        val withOpt = base.copyOf(base.size + 11)
        withOpt[11] = 1
        withOpt[base.size] = 0
        putU16(withOpt, base.size + 1, 41)
        putU16(withOpt, base.size + 3, 1232)
        putU32(withOpt, base.size + 5, 0)
        putU16(withOpt, base.size + 9, 0)
        assertTrue(DnsWireCodec.parseQuery(withOpt) is DnsQueryParseResult.Valid)
    }

    @Test
    fun malformedAndTruncatedQueriesAreRejected() {
        assertTrue(DnsWireCodec.parseQuery(byteArrayOf(1, 2, 3)) is DnsQueryParseResult.Malformed)
        val packet = query("example.com", 1).dropLast(2).toByteArray()
        assertTrue(DnsWireCodec.parseQuery(packet) is DnsQueryParseResult.Malformed)
    }

    @Test
    fun rejectsCompressionPointerLoop() {
        val packet = ByteArray(18)
        packet[0] = 1
        packet[5] = 1
        packet[12] = 0xc0.toByte()
        packet[13] = 12
        assertTrue(DnsWireCodec.parseQuery(packet) is DnsQueryParseResult.Malformed)
    }

    @Test
    fun responsePreservesIdQuestionAndRequestedErrorCode() {
        val parsed = (DnsWireCodec.parseQuery(query("example.com", 28, 0xabcd)) as DnsQueryParseResult.Valid).question
        val response = DnsWireCodec.responseFor(parsed, DnsRcode.NXDOMAIN)
        assertTrue(DnsWireCodec.isValidResponse(response, parsed))
        assertEquals(0xabcd, ((response[0].toInt() and 0xff) shl 8) or (response[1].toInt() and 0xff))
        assertEquals(DnsRcode.NXDOMAIN, response[3].toInt() and 0x0f)
    }

    @Test
    fun rejectsMismatchedTransactionIdAndMalformedAnswerSection() {
        val parsed = (DnsWireCodec.parseQuery(query("example.com", 1)) as DnsQueryParseResult.Valid).question
        val wrongId = DnsWireCodec.responseFor(parsed, DnsRcode.NOERROR).also { it[0] = (it[0] + 1).toByte() }
        assertFalse(DnsWireCodec.isValidResponse(wrongId, parsed))
        val trailing = DnsWireCodec.responseFor(parsed, DnsRcode.NOERROR) + byteArrayOf(1)
        assertFalse(DnsWireCodec.isValidResponse(trailing, parsed))
    }

    private fun query(host: String, type: Int, id: Int = 0x2468): ByteArray {
        val labels = host.split('.')
        val name = labels.flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        }.toByteArray() + byteArrayOf(0)
        val packet = ByteArray(12 + name.size + 4)
        putU16(packet, 0, id)
        putU16(packet, 2, 0x0100)
        putU16(packet, 4, 1)
        name.copyInto(packet, 12)
        putU16(packet, 12 + name.size, type)
        putU16(packet, 14 + name.size, 1)
        return packet
    }

    private fun putU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value ushr 8).toByte()
        packet[offset + 1] = value.toByte()
    }

    private fun putU32(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value ushr 24).toByte()
        packet[offset + 1] = (value ushr 16).toByte()
        packet[offset + 2] = (value ushr 8).toByte()
        packet[offset + 3] = value.toByte()
    }
}
