package com.manojarc20.tvadshield.dns

import com.manojarc20.tvadshield.filter.HostnameNormalizer
import com.manojarc20.tvadshield.filter.Rule
import com.manojarc20.tvadshield.filter.RuleEngine
import java.util.concurrent.TimeoutException

/** Policy-layer DNS input. This is not a wire-format DNS packet. */
data class DnsQuery(val hostname: String?)

/** DNS result codes used by the policy layer; packet encoding/transport is not implemented here. */
enum class DnsResponseCode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN
}

/** A transport-neutral policy-layer result, deliberately separate from DNS packet serialization. */
data class DnsResponse(val code: DnsResponseCode)

/**
 * Upstream resolver boundary. Implementations must honor timeoutMillis and throw
 * TimeoutException when the deadline expires. No real resolver is wired into V1.
 */
fun interface DnsResolver {
    @Throws(Exception::class)
    fun resolve(normalizedHostname: String, timeoutMillis: Long): DnsResponse
}

/**
 * Evaluates DNS host policy without Android APIs or a VPN dependency.
 *
 * A blocked host receives NXDOMAIN. Invalid input receives FORMERR. Allowed hosts are forwarded
 * to the injected resolver. A resolver timeout or exception becomes SERVFAIL: the component does
 * not silently fall back to an unfiltered resolver or fabricate NXDOMAIN.
 */
class DnsFilteringComponent(
    private val ruleEngine: RuleEngine,
    private val resolver: DnsResolver,
    private val resolverTimeoutMillis: Long = DEFAULT_RESOLVER_TIMEOUT_MILLIS
) {
    init {
        require(resolverTimeoutMillis > 0) { "resolverTimeoutMillis must be positive" }
    }

    fun process(query: DnsQuery): DnsResponse {
        val hostname = HostnameNormalizer.normalize(query.hostname)
            ?: return DnsResponse(DnsResponseCode.FORMERR)

        if (ruleEngine.decide(hostname) == Rule.Action.BLOCK) {
            return DnsResponse(DnsResponseCode.NXDOMAIN)
        }

        return try {
            resolver.resolve(hostname, resolverTimeoutMillis)
        } catch (_: TimeoutException) {
            DnsResponse(DnsResponseCode.SERVFAIL)
        } catch (_: Exception) {
            DnsResponse(DnsResponseCode.SERVFAIL)
        }
    }

    companion object {
        const val DEFAULT_RESOLVER_TIMEOUT_MILLIS = 2_000L
    }
}
