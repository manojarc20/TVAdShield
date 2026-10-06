package com.manojarc20.tvadshield.filter

import org.junit.Assert.assertEquals
import org.junit.Test

class RuleEngineTest {
    @Test
    fun exactDomainIsBlocked() =
        assertEquals(Rule.Action.BLOCK, RuleEngine(listOf(Rule("ads.example.com"))).decide("ads.example.com"))

    @Test
    fun subdomainIsBlocked() =
        assertEquals(Rule.Action.BLOCK, RuleEngine(listOf(Rule("ads.example.com"))).decide("video.ads.example.com"))

    @Test
    fun unrelatedDomainIsAllowed() =
        assertEquals(Rule.Action.ALLOW, RuleEngine(listOf(Rule("ads.example.com"))).decide("example.com"))

    @Test
    fun dotBoundaryPreventsFalsePositive() =
        assertEquals(Rule.Action.ALLOW, RuleEngine(listOf(Rule("ads.example.com"))).decide("notads.example.com"))

    @Test
    fun uppercaseAndTrailingRootDotAreNormalized() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        assertEquals(Rule.Action.BLOCK, engine.decide("ADS.EXAMPLE.COM."))
    }

    @Test
    fun unicodeHostnameIsConvertedToPunycode() {
        val engine = RuleEngine(listOf(Rule("xn--bcher-kva.example")))
        assertEquals(Rule.Action.BLOCK, engine.decide("BÜCHER.example"))
    }

    @Test
    fun exactOnlyRuleDoesNotMatchSubdomains() {
        val engine = RuleEngine(listOf(Rule("ads.example.com", includeSubdomains = false)))
        assertEquals(Rule.Action.BLOCK, engine.decide("ads.example.com"))
        assertEquals(Rule.Action.ALLOW, engine.decide("video.ads.example.com"))
    }

    @Test
    fun moreSpecificAllowOverridesParentBlock() {
        val engine = RuleEngine(
            listOf(Rule("safe.ads.example.com", Rule.Action.ALLOW), Rule("ads.example.com"))
        )
        assertEquals(Rule.Action.ALLOW, engine.decide("child.safe.ads.example.com"))
        assertEquals(Rule.Action.BLOCK, engine.decide("other.ads.example.com"))
    }

    @Test
    fun moreSpecificBlockOverridesParentAllow() {
        val engine = RuleEngine(
            listOf(Rule("example.com", Rule.Action.ALLOW), Rule("ads.example.com"))
        )
        assertEquals(Rule.Action.BLOCK, engine.decide("ads.example.com"))
        assertEquals(Rule.Action.ALLOW, engine.decide("safe.example.com"))
    }

    @Test
    fun allowWinsSameSpecificityRegardlessOfOrder() {
        val engine = RuleEngine(
            listOf(Rule("ads.example.com"), Rule("ads.example.com", Rule.Action.ALLOW))
        )
        assertEquals(Rule.Action.ALLOW, engine.decide("ads.example.com"))
    }

    @Test
    fun malformedAndEmptyInputsDoNotMatchRules() {
        val engine = RuleEngine(listOf(Rule("ads.example.com")))
        listOf(null, "", " ", ".example.com", "example..com", "example.com..",
            "https://example.com", "a b.example", "bad_.example")
            .forEach { assertEquals(Rule.Action.ALLOW, engine.decide(it)) }
    }

    @Test
    fun invalidRulePatternsAreIgnored() {
        assertEquals(
            Rule.Action.ALLOW,
            RuleEngine(listOf(Rule(""), Rule("https://ads.example.com"))).decide("ads.example.com")
        )
    }

    @Test
    fun largeRuleSetsUseSuffixTrieAndFindMostSpecificMatch() {
        val rules = (0 until 20_000).map { Rule("host$it.example.test") } +
            Rule("special.host19999.example.test", Rule.Action.ALLOW)
        val engine = RuleEngine(rules)
        assertEquals(Rule.Action.BLOCK, engine.decide("host19999.example.test"))
        assertEquals(Rule.Action.ALLOW, engine.decide("special.host19999.example.test"))
    }
}
