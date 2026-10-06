package com.manojarc20.tvadshield.filter

import java.net.IDN
import java.util.Locale

/**
 * Converts a DNS hostname to lowercase ASCII (including IDN punycode) or returns null when invalid.
 * A single trailing root dot is accepted. URLs, ports, empty labels, and malformed names are rejected.
 */
object HostnameNormalizer {
    fun normalize(hostname: String?): String? {
        val trimmed = hostname?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        if (trimmed.endsWith("..")) return null

        val withoutRootDot = if (trimmed.endsWith('.')) trimmed.dropLast(1) else trimmed
        if (withoutRootDot.isEmpty()) return null

        val ascii = try {
            IDN.toASCII(withoutRootDot, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) {
            return null
        }

        if (ascii.length > MAX_HOSTNAME_LENGTH) return null
        val labels = ascii.split('.')
        if (labels.any { label ->
                label.isEmpty() || label.length > MAX_LABEL_LENGTH
            }
        ) return null

        return ascii
    }

    private const val MAX_HOSTNAME_LENGTH = 253
    private const val MAX_LABEL_LENGTH = 63
}
