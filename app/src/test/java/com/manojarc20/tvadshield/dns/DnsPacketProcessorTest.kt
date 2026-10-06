package com.manojarc20.tvadshield.dns

import com.manojarc20.tvadshield.filter.Rule
import com.manojarc20.tvadshield.filter.RuleEngine
import java.util.concurrent.TimeoutException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPacketProcessorTest {
    @Test
    fun blockedQueryReturnsNxdomainWithoutUpstreamCall() {
        var called = false
        val processor = DnsPacketProcessor(
            RuleEngine(listOf(Rule("ads.example.com"))),
            DnsWireResolver { _, _ ->
                called = true
                error("Blocked query must not be forwarded")
            }
        )
        val response = processor.process(query("ads.example.com", 1))!!
        assertEquals(DnsRcode.NXDOMAIN, response[3].toInt() and 0x0f)
        assertFalse(called)
    }

    @Test
    fun allowedAQueryIsForwardedAndResponseValidated() {
        var called = false
        val processor = DnsPacketProcessor(
            RuleEngine(emptyList()),
            DnsWireResolver { query, _ ->
                called = true
                val parsed = (DnsWireCodec.parseQuery(query) as DnsQueryParseResult.Valid).question
                DnsWireCodec.responseFor(parsed, DnsRcode.NOERROR)
            }
        )
        val response = processor.process(query("www.example.com", 1))!!
        assertTrue(called)
        assertTrue(DnsWireCodec.isValidResponse(
            response,
            (DnsWireCodec.parseQuery(query("www.example.com", 1)) as DnsQueryParseResult.Valid).question
        ))
    }

    @Test
    fun allowedAaaaQueryRemainsAaaaUpstream() {
        var forwardedType = 0
        val processor = DnsPacketProcessor(
            RuleEngine(emptyList()),
            DnsWireResolver { query, _ ->
                val parsed = (DnsWireCodec.parseQuery(query) as DnsQueryParseResult.Valid).question
                forwardedType = parsed.queryType
                DnsWireCodec.responseFor(parsed, DnsRcode.NOERROR)
            }
        )
        processor.process(query("ipv6.example.com", 28))
        assertEquals(28, forwardedType)
    }

    @Test
    fun unsupportedTypeReturnsNotimpInsteadOfBecomingA() {
        var called = false
        val processor = DnsPacketProcessor(
            RuleEngine(emptyList()),
            DnsWireResolver { _, _ -> called = true; byteArrayOf() }
        )
        val response = processor.process(query("example.com", 15))!!
        assertEquals(DnsRcode.NOTIMP, response[3].toInt() and 0x0f)
        assertFalse(called)
    }

    @Test
    fun malformedQueryReturnsFormerr() {
        val processor = DnsPacketProcessor(RuleEngine(emptyList()), DnsWireResolver { _, _ -> error("unused") })
        val response = processor.process(query("example.com", 1).dropLast(1).toByteArray())!!
        assertEquals(DnsRcode.FORMERR, response[3].toInt() and 0x0f)
    }

    @Test
    fun upstreamTimeoutReturnsServfail() {
        val processor = DnsPacketProcessor(
            RuleEngine(emptyList()),
            DnsWireResolver { _, _ -> throw TimeoutException("timed out") }
        )
        val response = processor.process(query("example.com", 1))!!
        assertEquals(DnsRcode.SERVFAIL, response[3].toInt() and 0x0f)
    }

    @Test
    fun malformedOrMismatchedUpstreamResponseReturnsServfail() {
        val processor = DnsPacketProcessor(RuleEngine(emptyList()), DnsWireResolver { _, _ -> byteArrayOf(1, 2, 3) })
        val response = processor.process(query("example.com", 1))!!
        assertEquals(DnsRcode.SERVFAIL, response[3].toInt() and 0x0f)
    }

    @Test
    fun timeoutBudgetMustBePositive() {
        assertTrue(runCatching {
            DnsPacketProcessor(RuleEngine(emptyList()), DnsWireResolver { _, _ -> byteArrayOf() }, 0)
        }.isFailure)
    }

    private fun query(host: String, type: Int): ByteArray {
        val labels = host.split('.')
        val name = labels.flatMap { listOf(it.length.toByte()) + it.toByteArray(Charsets.US_ASCII).toList() }
            .toByteArray() + byteArrayOf(0)
        return ByteArray(12 + name.size + 4).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            name.copyInto(it, 12)
            val qtypeOffset = 12 + name.size
            it[qtypeOffset] = (type ushr 8).toByte()
            it[qtypeOffset + 1] = type.toByte()
            it[qtypeOffset + 3] = 1
        }
    }
}
