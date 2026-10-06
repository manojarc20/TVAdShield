package com.manojarc20.tvadshield.filter

/**
 * Deterministic hostname policy evaluator. Invalid input and unmatched hosts return ALLOW so the
 * core never invents a block decision; callers that process DNS must validate input separately.
 */
class RuleEngine(rules: List<Rule>) {
    private val normalizedRules = rules.mapNotNull { rule ->
        HostnameNormalizer.normalize(rule.pattern)?.let { normalized ->
            CompiledRule(normalized, rule.action, rule.includeSubdomains)
        }
    }

    /**
     * The most specific matching hostname rule wins. At equal specificity, ALLOW wins.
     * Rules match at DNS label boundaries, so example.com does not match notexample.com.
     */
    fun decide(hostname: String?): Rule.Action {
        val host = HostnameNormalizer.normalize(hostname) ?: return Rule.Action.ALLOW

        val matchingRule = normalizedRules
            .asSequence()
            .filter { it.matches(host) }
            .maxWithOrNull(
                compareBy<CompiledRule> { it.pattern.length }
                    .thenBy { if (host == it.pattern) 1 else 0 }
                    .thenBy { if (it.action == Rule.Action.ALLOW) 1 else 0 }
            )

        return matchingRule?.action ?: Rule.Action.ALLOW
    }

    private data class CompiledRule(
        val pattern: String,
        val action: Rule.Action,
        val includeSubdomains: Boolean
    ) {
        fun matches(host: String): Boolean =
            host == pattern || (includeSubdomains && host.endsWith(".$pattern"))
    }
}
