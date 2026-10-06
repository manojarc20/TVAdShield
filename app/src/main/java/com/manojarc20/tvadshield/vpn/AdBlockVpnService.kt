package com.manojarc20.tvadshield.vpn

import android.content.Intent
import android.net.VpnService

/**
 * Lifecycle-only safety gate. Dual-stack packet forwarding is not complete, so this service must
 * not configure routes or establish a TUN. The start action follows STARTING -> ERROR -> STOPPED.
 */
class AdBlockVpnService : VpnService() {
    private val lifecycle = VpnStateMachine()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (lifecycle.state != VpnState.STOPPED) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        lifecycle.transitionTo(VpnState.STARTING)
        if (!VpnReleaseGate.mayEstablishVpn()) {
            lifecycle.transitionTo(VpnState.ERROR)
            stopSelf(startId)
            return START_NOT_STICKY
        }

        // Intentionally no Builder or establish() call exists until the dual-stack gate is met.
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

    companion object {
        const val ACTION_STOP = "com.manojarc20.tvadshield.action.STOP"
    }
}
