package com.manojarc20.tvadshield.dns

import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

class DnsTcpFrameCodecTest {
    @Test
    fun encodesAndReadsAFrame() {
        val message = ByteArray(12) { it.toByte() }
        val framed = DnsTcpFrameCodec.encode(message)

        assertEquals(0, framed[0].toInt())
        assertEquals(12, framed[1].toInt())
        assertArrayEquals(message, DnsTcpFrameCodec.readFrame(ByteArrayInputStream(framed)))
    }

    @Test
    fun readsMultipleFramesFromOneStream() {
        val first = ByteArray(12) { 1 }
        val second = ByteArray(300) { 2 }
        val stream = ByteArrayInputStream(
            DnsTcpFrameCodec.encode(first) + DnsTcpFrameCodec.encode(second)
        )

        assertArrayEquals(first, DnsTcpFrameCodec.readFrame(stream))
        assertArrayEquals(second, DnsTcpFrameCodec.readFrame(stream))
        assertNull(DnsTcpFrameCodec.readFrame(stream))
    }

    @Test
    fun cleanEofBeforeFrameReturnsNull() {
        assertNull(DnsTcpFrameCodec.readFrame(ByteArrayInputStream(byteArrayOf())))
    }

    @Test
    fun truncatedLengthPrefixIsRejected() {
        assertThrows<EOFException> {
            DnsTcpFrameCodec.readFrame(ByteArrayInputStream(byteArrayOf(0)))
        }
    }

    @Test
    fun truncatedMessageBodyIsRejected() {
        assertThrows<EOFException> {
            DnsTcpFrameCodec.readFrame(ByteArrayInputStream(byteArrayOf(0, 12, 1, 2)))
        }
    }

    @Test
    fun invalidDnsLengthsAreRejected() {
        for (length in listOf(0, 11)) {
            assertThrows<IOException> {
                DnsTcpFrameCodec.readFrame(
                    ByteArrayInputStream(byteArrayOf((length ushr 8).toByte(), length.toByte()))
                )
            }
        }
    }

    @Test
    fun invalidMessagesCannotBeEncoded() {
        for (message in listOf(ByteArray(0), ByteArray(11))) {
            try {
                DnsTcpFrameCodec.encode(message)
                fail("Expected invalid DNS message size to be rejected")
            } catch (_: IllegalArgumentException) {
                // Expected.
            }
        }
    }

    private inline fun <reified T : Throwable> assertThrows(block: () -> Unit) {
        try {
            block()
            fail("Expected ${T::class.java.simpleName}")
        } catch (failure: Throwable) {
            if (failure !is T) throw failure
        }
    }
}
