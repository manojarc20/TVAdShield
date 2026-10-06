package com.manojarc20.tvadshield.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class DnsOverTlsServer(
    val tlsHostname: String,
    val numericAddress: String,
    val port: Int = 853
) {
    init {
        require(tlsHostname.isNotBlank())
        require(port in 1..65535)
    }
}

/**
 * DNS-over-TLS resolver with certificate/hostname verification, numeric upstream addresses,
 * bounded total timeout, per-query socket cleanup, and an injected socket-protection hook.
 * The hook is mandatory so a future VPN integration cannot accidentally recurse into its own TUN.
 */
class DnsOverTlsResolver(
    private val servers: List<DnsOverTlsServer> = DEFAULT_SERVERS,
    private val socketProtector: (Socket) -> Boolean,
    private val connectTimeoutMillis: Int = 2_000,
    private val readTimeoutMillis: Int = 2_000,
    private val socketFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
) : DnsWireResolver {
    init {
        require(servers.isNotEmpty())
        require(connectTimeoutMillis > 0 && readTimeoutMillis > 0)
    }

    override fun resolve(queryPacket: ByteArray, timeoutMillis: Long): ByteArray {
        require(timeoutMillis > 0)
        val parsed = DnsWireCodec.parseQuery(queryPacket)
        require(parsed is DnsQueryParseResult.Valid) { "Resolver requires a valid DNS query" }
        val expected = parsed.question
        val budgetNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val startedAt = System.nanoTime()
        var lastFailure: Exception? = null

        for (server in servers) {
            if (Thread.currentThread().isInterrupted) {
                throw InterruptedException("DNS resolution cancelled")
            }
            val remainingNanos = budgetNanos - (System.nanoTime() - startedAt)
            if (remainingNanos <= 0) break
            val remainingMillis = TimeUnit.NANOSECONDS.toMillis(remainingNanos).coerceAtLeast(1)
                .coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            try {
                return queryOne(server, queryPacket, expected, remainingMillis)
            } catch (failure: InterruptedException) {
                Thread.currentThread().interrupt()
                throw failure
            } catch (failure: Exception) {
                lastFailure = failure
            }
        }

        if (lastFailure == null || lastFailure is java.net.SocketTimeoutException ||
            System.nanoTime() - startedAt >= budgetNanos
        ) {
            throw TimeoutException("DNS-over-TLS resolution exceeded its time budget").also {
                lastFailure?.let(it::addSuppressed)
            }
        }
        throw IOException("All DNS-over-TLS upstreams failed", lastFailure)
    }

    private fun queryOne(
        server: DnsOverTlsServer,
        queryPacket: ByteArray,
        expected: DnsQuestion,
        timeoutMillis: Int
    ): ByteArray {
        val address = numericAddress(server.numericAddress)
        val startedAt = System.nanoTime()
        val transportSocket = Socket()
        try {
            if (!socketProtector(transportSocket)) {
                throw IOException("Could not protect DNS-over-TLS socket")
            }
            transportSocket.connect(
                InetSocketAddress(address, server.port),
                minOf(connectTimeoutMillis, timeoutMillis)
            )
            val tlsSocket = socketFactory.createSocket(
                transportSocket,
                server.tlsHostname,
                server.port,
                true
            ) as SSLSocket
            tlsSocket.use { socket ->
                var remaining = remainingMillis(startedAt, timeoutMillis)
                socket.soTimeout = minOf(readTimeoutMillis, remaining)
                val parameters = socket.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                parameters.serverNames = listOf(SNIHostName(server.tlsHostname))
                socket.sslParameters = parameters
                socket.startHandshake()

                remaining = remainingMillis(startedAt, timeoutMillis)
                socket.soTimeout = minOf(readTimeoutMillis, remaining)
                val output = DataOutputStream(socket.outputStream)
                output.writeShort(queryPacket.size)
                output.write(queryPacket)
                output.flush()

                val input = DataInputStream(socket.inputStream)
                val responseLength = input.readUnsignedShort()
                if (responseLength < 12) throw IOException("Truncated DNS-over-TLS response")
                val response = ByteArray(responseLength)
                input.readFully(response)
                if (!DnsWireCodec.isValidResponse(response, expected)) {
                    throw IOException("Mismatched or malformed DNS-over-TLS response")
                }
                return response
            }
        } finally {
            runCatching { transportSocket.close() }
        }
    }

    private fun remainingMillis(startedAt: Long, budgetMillis: Int): Int {
        val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
        val remaining = budgetMillis - elapsedMillis
        if (remaining <= 0) throw java.net.SocketTimeoutException("DNS-over-TLS time budget expired")
        return remaining.toInt()
    }

    private fun numericAddress(value: String): InetAddress {
        return if (':' in value) {
            require(value.matches(Regex("[0-9a-fA-F:.]+"))) { "Upstream address must be numeric IPv6" }
            (InetAddress.getByName(value) as? Inet6Address)
                ?: throw IllegalArgumentException("Upstream address is not IPv6")
        } else {
            val parts = value.split('.')
            require(parts.size == 4 && parts.all { it.isNotEmpty() && it.all(Char::isDigit) }) {
                "Upstream address must be numeric IPv4 or IPv6"
            }
            val octets = parts.map { it.toIntOrNull()?.takeIf { octet -> octet in 0..255 }
                ?: throw IllegalArgumentException("Invalid IPv4 address") }
            InetAddress.getByAddress(octets.map(Int::toByte).toByteArray())
        }
    }

    companion object {
        /** Cloudflare DNS-over-TLS endpoints, with TLS hostname verification enabled. */
        val DEFAULT_SERVERS = listOf(
            DnsOverTlsServer("cloudflare-dns.com", "1.1.1.1"),
            DnsOverTlsServer("cloudflare-dns.com", "1.0.0.1"),
            DnsOverTlsServer("cloudflare-dns.com", "2606:4700:4700::1111"),
            DnsOverTlsServer("cloudflare-dns.com", "2606:4700:4700::1001")
        )
    }
}
