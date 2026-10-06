package com.manojarc20.tvadshield.filter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleListParserTest {
    @Test
    fun parsesActionsCommentsAndNormalizesHosts() {
        val result = RuleListParser.parse(
            listOf(
                "# comment",
                "BLOCK ADS.Example.COM.",
                "allow safe.ads.example.com # exception",
                ""
            )
        )
        assertEquals(2, result.rules.size)
        assertEquals(Rule.Action.BLOCK, result.rules[0].action)
        assertEquals("ads.example.com", result.rules[0].pattern)
        assertEquals(Rule.Action.ALLOW, result.rules[1].action)
        assertEquals("safe.ads.example.com", result.rules[1].pattern)
        assertEquals(0, result.invalidEntries)
    }

    @Test
    fun ignoresMalformedLinesAndHostnames() {
        val result = RuleListParser.parse(
            listOf("permit ads.example.com", "block", "block https://ads.example.com", "block bad..example")
        )
        assertTrue(result.rules.isEmpty())
        assertEquals(4, result.invalidEntries)
    }

    @Test
    fun deduplicatesNormalizedActionAndHostnamePairs() {
        val result = RuleListParser.parse(listOf("block Ads.example.com", "BLOCK ads.example.com."))
        assertEquals(1, result.rules.size)
        assertEquals(1, result.duplicateEntries)
    }

    @Test
    fun allowAndBlockForSameHostRemainDistinctRules() {
        val result = RuleListParser.parse(listOf("block ads.example.com", "allow ads.example.com"))
        assertEquals(2, result.rules.size)
        assertEquals(Rule.Action.ALLOW, RuleEngine(result.rules).decide("ads.example.com"))
    }

    @Test
    fun enforcesMaximumRuleCount() {
        val result = RuleListParser.parse(listOf("block a.example", "block b.example"), maxRules = 1)
        assertEquals(1, result.rules.size)
        assertTrue(result.exceededLimit)
    }
}
