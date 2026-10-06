package com.manojarc20.tvadshield.filter

class RuleEngine(rules: List<Rule>) {
    private val rules = rules.map { it.copy(pattern = normalize(it.pattern)) }.filter { it.pattern.isNotEmpty() }

    fun decide(hostname: String): Rule.Action {
        val host = normalize(hostname)
        if (host.isEmpty()) return Rule.Action.ALLOW
        var decision = Rule.Action.ALLOW
        for (rule in rules) {
            if (host == rule.pattern || host.endsWith(".${rule.pattern}")) decision = rule.action
        }
        return decision
    }

    private fun normalize(value: String): String = value.trim().lowercase().trimEnd('.')
}
