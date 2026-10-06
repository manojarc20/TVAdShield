package com.manojarc20.tvadshield.filter

import org.junit.Assert.assertEquals
import org.junit.Test

class RuleEngineTest {
    private val engine = RuleEngine(listOf(
        Rule("ads.example.com"),
        Rule("tracker.example"),
        Rule("safe.ads.example.com", Rule.Action.ALLOW)
    ))

    @Test fun exactDomainIsBlocked() = assertEquals(Rule.Action.BLOCK, engine.decide("ads.example.com"))
    @Test fun subdomainIsBlocked() = assertEquals(Rule.Action.BLOCK, engine.decide("video.ads.example.com"))
    @Test fun unrelatedDomainIsAllowed() = assertEquals(Rule.Action.ALLOW, engine.decide("example.com"))
    @Test fun boundaryPreventsFalsePositive() = assertEquals(Rule.Action.ALLOW, engine.decide("notads.example.com"))
    @Test fun explicitAllowOverridesEarlierBlock() = assertEquals(Rule.Action.ALLOW, engine.decide("safe.ads.example.com"))
}
