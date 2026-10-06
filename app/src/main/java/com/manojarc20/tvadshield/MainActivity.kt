package com.manojarc20.tvadshield

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.manojarc20.tvadshield.vpn.AdBlockVpnService

/** TV-remote-friendly status screen. Protection remains off until full dual-stack forwarding is ready. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(64, 40, 64, 40)
            isFocusable = true
        }

        root.addView(TextView(this).apply {
            text = "TVAdShield"
            textSize = 36f
            gravity = Gravity.CENTER
        })

        root.addView(TextView(this).apply {
            text = "Protection: OFF"
            textSize = 28f
            gravity = Gravity.CENTER
            setPadding(0, 32, 0, 8)
        })

        root.addView(TextView(this).apply {
            text = "VPN is not ready. IPv4 and IPv6 forwarding for DNS and other traffic must be implemented and tested before protection can start. Your network is not routed through TVAdShield."
            textSize = 20f
            gravity = Gravity.CENTER
            setPadding(0, 8, 0, 24)
        })

        root.addView(Button(this).apply {
            text = "START PROTECTION — NOT READY"
            isEnabled = false
            contentDescription = "Start protection is disabled until IPv4 and IPv6 forwarding is implemented and tested"
            minHeight = 64
        })

        root.addView(Button(this).apply {
            text = "STOP PROTECTION"
            contentDescription = "Emergency stop"
            minHeight = 64
            setOnClickListener {
                stopService(Intent(this@MainActivity, AdBlockVpnService::class.java))
            }
        })

        root.addView(TextView(this).apply {
            text = "No DNS history or telemetry is collected. Filtering is not active."
            textSize = 16f
            gravity = Gravity.CENTER
            setPadding(0, 24, 0, 0)
        })

        setContentView(root)
    }
}
