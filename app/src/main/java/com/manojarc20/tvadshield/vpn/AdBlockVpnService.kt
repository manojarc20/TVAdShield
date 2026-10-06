package com.manojarc20.tvadshield.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

/** Safety-first placeholder. It intentionally does NOT establish a VPN yet. */
class AdBlockVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Do not establish an incomplete VPN: it could black-hole TV traffic.
        stopSelf(startId)
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }
}
