package com.manojarc20.tvadshield.vpn

import android.content.Intent
import android.net.VpnService

/**
 * Android lifecycle adapter only. Packet transport, DNS processing, rule evaluation, statistics,
 * and UI state are separate layers and are not wired to this service yet.
 */
class AdBlockVpnService : VpnService() {
    private val lifecycle = VpnStateMachine()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Never establish an incomplete tunnel. Report an explicit internal error and stop.
        if (lifecycle.state != VpnState.STOPPED) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        lifecycle.transitionTo(VpnState.STARTING)
        lifecycle.transitionTo(VpnState.ERROR)
        stopSelf(startId)
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        if (lifecycle.state != VpnState.STOPPED) {
            if (lifecycle.state != VpnState.STOPPING) {
                lifecycle.transitionTo(VpnState.STOPPING)
            }
            lifecycle.transitionTo(VpnState.STOPPED)
        }
        super.onDestroy()
    }
}
