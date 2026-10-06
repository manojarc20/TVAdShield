package com.manojarc20.tvadshield.dns

import com.manojarc20.tvadshield.filter.Rule
import com.manojarc20.tvadshield.filter.RuleEngine
import java.util.concurrent.TimeoutException

/** Isolated upstream boundary; implementations may use DoT or a local test resolver. */
fun interface DnsWireResolver {
    @Throws(Exception::class)
    fun resolve(queryPacket: ByteArray, timeoutMillis: Long): ByteArray
}

/**
 * Applies hostname policy to one UDP DNS message. Only IN A and AAAA queries are sent upstream;
 * other types return NOTIMP rather than being rewritten as A. Resolver failures return SERVFAIL.
 */
class DnsPacketProcessor(
    private val ruleEngine: RuleEngine,
    private val resolver: DnsWireResolver,
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS
) {
    init {
        require(timeoutMillis > 0)
    }

    fun process(packet: ByteArray): ByteArray? {
        val parsed = DnsWireCodec.parseQuery(packet)
        if (parsed !is DnsQueryParseResult.Valid) {
            return DnsWireCodec.errorResponse(packet, DnsRcode.FORMERR)
        }

        val question = parsed.question
        if (question.queryClass != CLASS_IN ||
            (question.queryType != TYPE_A && question.queryType != TYPE_AAAA)
        ) {
            return DnsWireCodec.responseFor(question, DnsRcode.NOTIMP)
        }

        if (ruleEngine.decide(question.hostname) == Rule.Action.BLOCK) {
            return DnsWireCodec.responseFor(question, DnsRcode.NXDOMAIN)
        }

        return try {
            val response = resolver.resolve(question.originalPacket.copyOf(), timeoutMillis)
            if (DnsWireCodec.isValidResponse(response, question)) {
                response.copyOf()
            } else {
                DnsWireCodec.responseFor(question, DnsRcode.SERVFAIL)
            }
        } catch (_: TimeoutException) {
            DnsWireCodec.responseFor(question, DnsRcode.SERVFAIL)
        } catch (_: Exception) {
            DnsWireCodec.responseFor(question, DnsRcode.SERVFAIL)
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 2_000L
        private const val CLASS_IN = 1
        private const val TYPE_A = 1
        private const val TYPE_AAAA = 28
    }
}
