package com.manojarc20.tvadshield.filter

/**
 * Parses a deliberately small first-party rule format:
 *   block example.com
 *   allow safe.example.com
 *
 * Blank lines and text after # are ignored. Invalid entries and duplicates are reported and
 * skipped. Parsing is bounded to avoid loading unexpectedly large rule sources into memory.
 */
object RuleListParser {
    const val DEFAULT_MAX_RULES = 50_000

    data class Result(
        val rules: List<Rule>,
        val invalidEntries: Int,
        val duplicateEntries: Int,
        val exceededLimit: Boolean
    )

    fun parse(lines: Iterable<String>, maxRules: Int = DEFAULT_MAX_RULES): Result {
        require(maxRules >= 0) { "maxRules must not be negative" }
        val rules = ArrayList<Rule>()
        val seen = HashSet<Pair<String, Rule.Action>>()
        var invalid = 0
        var duplicates = 0
        var exceeded = false

        for (rawLine in lines) {
            val line = rawLine.substringBefore('#').trim()
            if (line.isEmpty()) continue
            val fields = line.split(Regex("\\s+"))
            if (fields.size != 2) {
                invalid++
                continue
            }
            val action = when (fields[0].lowercase()) {
                "block" -> Rule.Action.BLOCK
                "allow" -> Rule.Action.ALLOW
                else -> null
            }
            val hostname = HostnameNormalizer.normalize(fields[1])
            if (action == null || hostname == null) {
                invalid++
                continue
            }
            val key = hostname to action
            if (!seen.add(key)) {
                duplicates++
                continue
            }
            if (rules.size >= maxRules) {
                exceeded = true
                continue
            }
            rules += Rule(hostname, action)
        }

        return Result(rules, invalid, duplicates, exceeded)
    }
}
