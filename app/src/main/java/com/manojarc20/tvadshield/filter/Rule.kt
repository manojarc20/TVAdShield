package com.manojarc20.tvadshield.filter

/**
 * A hostname rule. Matching is case-insensitive and performed against normalized ASCII hostnames.
 *
 * @param includeSubdomains when true, the rule matches the exact hostname and its dot-boundary
 * subdomains. When false, only the exact hostname matches.
 */
data class Rule(
    val pattern: String,
    val action: Action = Action.BLOCK,
    val includeSubdomains: Boolean = true
) {
    enum class Action { BLOCK, ALLOW }
}
