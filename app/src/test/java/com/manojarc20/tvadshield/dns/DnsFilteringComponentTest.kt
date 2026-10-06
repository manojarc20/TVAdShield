package com.manojarc20.tvadshield.dns

import com.manojarc20.tvadshield.filter.Rule
import com.manojarc20.tvadshield.filter.RuleEngine
import java.io.IOException
import java.util.concurrent.TimeoutException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsFilteringComponentTest {
    @Test
    fun blockedDomainReturnsNxdomainWithoutCallingResolver() {
        var resolverCalled = false
        val component = DnsFilteringComponent(
            RuleEngine(listOf(Rule("ads.example.com"))),
            DnsResolver { _, _ ->
                resolverCalled = true
                DnsResponse(DnsResponseCode.NOERROR)
            }
        )

        assertEquals(
            DnsResponseCode.NXDOMAIN,
            component.process(DnsQuery("ads.example.com")).code
        )
        assertFalse(resolverCalled)
    }

    @Test
    fun allowedDomainIsForwardedAndResolverResponseIsReturned() {
        var forwardedHostname: String? = null
        var forwardedTimeout: Long? = null
        val resolved = DnsResponse(DnsResponseCode.NOERROR)
        val component = DnsFilteringComponent(
            RuleEngine(listOf(Rule("ads.example.com"))),
            DnsResolver { hostname, timeout ->
                forwardedHostname = hostname
                forwardedTimeout = timeout
                resolved
            },
            resolverTimeoutMillis = 750
        )

        assertEquals(resolved, component.process(DnsQuery("WWW.Example.COM.")))
        assertEquals("www.example.com", forwardedHostname)
        assertEquals(750L, forwardedTimeout)
    }

    @Test
    fun subdomainOfBlockedDomainIsBlocked() {
        val component = DnsFilteringComponent(
            RuleEngine(listOf(Rule("ads.example.com"))),
            DnsResolver { _, _ -> error("Blocked query must not reach resolver") }
        )

        assertEquals(
            DnsResponseCode.NXDOMAIN,
            component.process(DnsQuery("video.ads.example.com")).code
        )
    }

    @Test
    fun allowRuleOverridesLessSpecificBlock() {
        val component = DnsFilteringComponent(
            RuleEngine(
                listOf(
                    Rule("safe.ads.example.com", Rule.Action.ALLOW),
                    Rule("ads.example.com", Rule.Action.BLOCK)
                )
            ),
            DnsResolver { _, _ -> DnsResponse(DnsResponseCode.NOERROR) }
        )

        assertEquals(
            DnsResponseCode.NOERROR,
            component.process(DnsQuery("safe.ads.example.com")).code
        )
    }

    @Test
    fun malformedQueryReturnsFormerrWithoutCallingResolver() {
        var resolverCalled = false
        val component = DnsFilteringComponent(
            RuleEngine(emptyList()),
            DnsResolver { _, _ ->
                resolverCalled = true
                DnsResponse(DnsResponseCode.NOERROR)
            }
        )

        assertEquals(DnsResponseCode.FORMERR, component.process(DnsQuery("bad..example")).code)
        assertEquals(DnsResponseCode.FORMERR, component.process(DnsQuery("")).code)
        assertFalse(resolverCalled)
    }

    @Test
    fun resolverFailureReturnsServfail() {
        val component = DnsFilteringComponent(
            RuleEngine(emptyList()),
            DnsResolver { _, _ -> throw IOException("upstream unavailable") }
        )

        assertEquals(
            DnsResponseCode.SERVFAIL,
            component.process(DnsQuery("www.example.com")).code
        )
    }

    @Test
    fun resolverTimeoutReturnsServfail() {
        val component = DnsFilteringComponent(
            RuleEngine(emptyList()),
            DnsResolver { _, _ -> throw TimeoutException("deadline exceeded") }
        )

        assertEquals(
            DnsResponseCode.SERVFAIL,
            component.process(DnsQuery("www.example.com")).code
        )
    }

    @Test
    fun resolverTimeoutMustBePositive() {
        assertTrue(
            runCatching {
                DnsFilteringComponent(
                    RuleEngine(emptyList()),
                    DnsResolver { _, _ -> DnsResponse(DnsResponseCode.NOERROR) },
                    resolverTimeoutMillis = 0
                )
            }.isFailure
        )
    }
}
