package com.manojarc20.tvadshield.filter

/**
 * JVM-only hostname policy. Rules are stored in a reversed-label trie, so lookup visits only
 * suffixes of the queried hostname rather than scanning every rule.
 */
class RuleEngine(rules: List<Rule>) {
    private val root = Node()

    init {
        rules.forEach { rule ->
            val pattern = HostnameNormalizer.normalize(rule.pattern) ?: return@forEach
            val labels = pattern.split('.')
            var node = root
            labels.asReversed().forEach { label ->
                node = node.children.getOrPut(label) { Node() }
            }
            node.rules += CompiledRule(pattern, labels.size, rule.action, rule.includeSubdomains)
        }
    }

    /**
     * Most-specific matching rule wins. More labels are more specific; for a same-depth match,
     * an exact-host match wins. ALLOW wins a remaining tie. Invalid and unmatched hosts return
     * ALLOW, while DNS callers validate malformed input separately.
     */
    fun decide(hostname: String?): Rule.Action {
        val host = HostnameNormalizer.normalize(hostname) ?: return Rule.Action.ALLOW
        val labels = host.split('.')
        var node = root
        var best: CompiledRule? = null
        var depth = 0

        for (label in labels.asReversed()) {
            node = node.children[label] ?: break
            depth++
            node.rules.forEach { candidate ->
                val exact = depth == labels.size
                if ((candidate.includeSubdomains || exact) && isBetter(candidate, exact, best, host)) {
                    best = candidate
                }
            }
        }
        return best?.action ?: Rule.Action.ALLOW
    }

    private fun isBetter(
        candidate: CompiledRule,
        exact: Boolean,
        current: CompiledRule?,
        host: String
    ): Boolean {
        if (current == null) return true
        val currentExact = host == current.pattern
        if (candidate.labelCount != current.labelCount) return candidate.labelCount > current.labelCount
        if (exact != currentExact) return exact
        if (candidate.action != current.action) return candidate.action == Rule.Action.ALLOW
        return false
    }

    private class Node {
        val children = HashMap<String, Node>()
        val rules = ArrayList<CompiledRule>()
    }

    private data class CompiledRule(
        val pattern: String,
        val labelCount: Int,
        val action: Rule.Action,
        val includeSubdomains: Boolean
    )
}
