package com.manojarc20.tvadshield

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 32, 48, 32)
        }
        root.addView(TextView(this).apply {
            text = "TVAdShield"
            textSize = 32f
            gravity = Gravity.CENTER
        })
        root.addView(TextView(this).apply {
            text = "\\nV1 development build\\n\\nFiltering is NOT active yet.\\nYour TV network connection is untouched."
            textSize = 20f
            gravity = Gravity.CENTER
            setPadding(0, 24, 0, 0)
        })
        setContentView(root)
    }
}
