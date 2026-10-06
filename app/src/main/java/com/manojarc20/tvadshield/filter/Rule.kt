package com.manojarc20.tvadshield.filter

data class Rule(
    val pattern: String,
    val action: Action = Action.BLOCK
) {
    enum class Action { BLOCK, ALLOW }
}
