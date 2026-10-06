package com.manojarc20.tvadshield.dns

import java.io.EOFException
import java.io.IOException
import java.io.InputStream

/**
 * DNS-over-TCP two-byte length framing. Each decoded message is bounded by the wire-format
 * maximum and can be passed to the same DNS policy used for UDP.
 */
object DnsTcpFrameCodec {
    private const val MIN_DNS_MESSAGE_SIZE = 12
    private const val MAX_DNS_MESSAGE_SIZE = 65_535

    fun encode(message: ByteArray): ByteArray {
        require(message.size in MIN_DNS_MESSAGE_SIZE..MAX_DNS_MESSAGE_SIZE) {
            "DNS-over-TCP message length is outside the DNS wire-format bounds"
        }
        return ByteArray(message.size + 2).also {
            it[0] = (message.size ushr 8).toByte()
            it[1] = message.size.toByte()
            message.copyInto(it, destinationOffset = 2)
        }
    }

    /**
     * Returns null only for clean EOF before a frame begins. Truncated prefixes/bodies and
     * invalid DNS message lengths throw, so a caller can close the malformed TCP conversation.
     */
    @Throws(IOException::class)
    fun readFrame(input: InputStream): ByteArray? {
        val high = input.read()
        if (high < 0) return null
        val low = input.read()
        if (low < 0) throw EOFException("Truncated DNS-over-TCP length prefix")

        val length = (high shl 8) or low
        if (length !in MIN_DNS_MESSAGE_SIZE..MAX_DNS_MESSAGE_SIZE) {
            throw IOException("Invalid DNS-over-TCP frame length: $length")
        }

        val message = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val count = input.read(message, offset, length - offset)
            if (count < 0) throw EOFException("Truncated DNS-over-TCP message")
            if (count == 0) continue
            offset += count
        }
        return message
    }
}
