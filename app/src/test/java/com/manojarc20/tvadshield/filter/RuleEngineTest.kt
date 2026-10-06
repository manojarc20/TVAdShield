package com.manojarc20.tvadshield.filter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RuleEngineTest {
    @Test
    fun exactDomainIsBlocked() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        assertEquals(Rule.Action.BLOCK, engine.decide("ads.example.com"))
    }

    @Test
    fun subdomainIsBlocked() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        assertEquals(Rule.Action.BLOCK, engine.decide("video.ads.example.com"))
    }

    @Test
    fun unrelatedDomainIsAllowed() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        assertEquals(Rule.Action.ALLOW, engine.decide("example.com"))
    }

    @Test
    fun dotBoundaryPreventsFalsePositive() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        assertEquals(Rule.Action.ALLOW, engine.decide("notads.example.com"))
    }

    @Test
    fun uppercaseHostnameIsNormalized() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        assertEquals(Rule.Action.BLOCK, engine.decide("ADS.EXAMPLE.COM"))
    }

    @Test
    fun trailingRootDotIsNormalized() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        assertEquals(Rule.Action.BLOCK, engine.decide("ads.example.com."))
    }

    @Test
    fun unicodeHostnameIsNormalizedToPunycode() {
        val engine = RuleEngine(listOf(Rule("xn--bcher-kva.example")))
        assertEquals(Rule.Action.BLOCK, engine.decide("BÜCHER.example."))
    }

    @Test
    fun exactOnlyRuleDoesNotMatchSubdomains() {
        val engine = RuleEngine(listOf(Rule("ads.example.com", includeSubdomains = false)))
        assertEquals(Rule.Action.BLOCK, engine.decide("ads.example.com"))
        assertEquals(Rule.Action.ALLOW, engine.decide("video.ads.example.com"))
    }

    @Test
    fun moreSpecificAllowOverridesParentBlockRegardlessOfOrder() {
        val engine = RuleEngine(
            listOf(
                Rule("safe.ads.example.com", Rule.Action.ALLOW),
                Rule("ads.example.com", Rule.Action.BLOCK)
            )
        )
        assertEquals(Rule.Action.ALLOW, engine.decide("safe.ads.example.com"))
        assertEquals(Rule.Action.ALLOW, engine.decide("child.safe.ads.example.com"))
        assertEquals(Rule.Action.BLOCK, engine.decide("other.ads.example.com"))
    }

    @Test
    fun moreSpecificBlockOverridesParentAllow() {
        val engine = RuleEngine(
            listOf(
                Rule("example.com", Rule.Action.ALLOW),
                Rule("ads.example.com", Rule.Action.BLOCK)
            )
        )
        assertEquals(Rule.Action.BLOCK, engine.decide("ads.example.com"))
        assertEquals(Rule.Action.ALLOW, engine.decide("safe.example.com"))
    }

    @Test
    fun allowWinsWhenMatchingRulesHaveEqualSpecificity() {
        val engine = RuleEngine(
            listOf(
                Rule("ads.example.com", Rule.Action.BLOCK),
                Rule("ads.example.com", Rule.Action.ALLOW)
            )
        )
        assertEquals(Rule.Action.ALLOW, engine.decide("ads.example.com"))
    }

    @Test
    fun invalidAndEmptyHostnamesDefaultToAllowInCore() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        listOf(null, "", " ", ".example.com", "example..com", "example.com..", "https://example.com", "a b.example")
            .forEach { hostname ->
                assertEquals("Unexpected decision for $hostname", Rule.Action.ALLOW, engine.decide(hostname))
            }
    }

    @Test
    fun invalidRulesAreIgnored() {
        val engine = RuleEngine(listOf(Rule(""), Rule("https://ads.example.com")))
        assertEquals(Rule.Action.ALLOW, engine.decide("ads.example.com"))
    }

    @Test
    fun emptyRuleSetAllowsValidHostnames() {
        assertEquals(Rule.Action.ALLOW, RuleEngine(emptyList()).decide("example.com"))
    }

    @Test
    fun normalizerRejectsMalformedNamesAndAcceptsOneRootDot() {
        assertEquals("example.com", HostnameNormalizer.normalize(" Example.COM. "))
        assertNull(HostnameNormalizer.normalize(null))
        assertNull(HostnameNormalizer.normalize(""))
        assertNull(HostnameNormalizer.normalize("example..com"))
        assertNull(HostnameNormalizer.normalize("example.com.."))
        assertNull(HostnameNormalizer.normalize("-bad.example"))
        assertNull(HostnameNormalizer.normalize("bad_.example"))
    }
}
