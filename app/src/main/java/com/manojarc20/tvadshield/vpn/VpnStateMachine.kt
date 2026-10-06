package com.manojarc20.tvadshield.vpn

/** Lifecycle states only; packet transport and filtering are separate, currently unwired layers. */
enum class VpnState {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    ERROR
}

/** Pure JVM state transition guard used by the Android service lifecycle adapter. */
class VpnStateMachine {
    var state: VpnState = VpnState.STOPPED
        private set

    fun transitionTo(next: VpnState) {
        val allowed = when (state) {
            VpnState.STOPPED -> setOf(VpnState.STARTING)
            VpnState.STARTING -> setOf(VpnState.RUNNING, VpnState.STOPPING, VpnState.ERROR)
            VpnState.RUNNING -> setOf(VpnState.STOPPING, VpnState.ERROR)
            VpnState.STOPPING -> setOf(VpnState.STOPPED, VpnState.ERROR)
            VpnState.ERROR -> setOf(VpnState.STOPPING, VpnState.STOPPED)
        }
        check(next in allowed) { "Invalid VPN state transition: $state -> $next" }
        state = next
    }
}
