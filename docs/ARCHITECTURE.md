# TVAdShield Architecture and Readiness

## Release status

This is a development candidate, **not ready for physical Android/Google TV testing**. Protection is OFF. The UI disables Start. The service contains no VPN Builder or TUN establishment call and terminates every start attempt. No application traffic currently enters TVAdShield.

## Platform support

The Android app declares API 24 (Android 7.0) as its minimum because the resolver relies on secure TLS hostname verification and SNI APIs introduced there. The app targets Android TV/Google TV; actual vendor compatibility still needs emulator and physical-device validation.

## Domain rules

The filtering core is JVM-only. Hostnames are trimmed, converted to lowercase ASCII using IDN punycode, and accept one trailing DNS root dot. Malformed names do not match. Rules support exact hosts or hosts plus subdomains. A reversed-label trie gives suffix lookup proportional to hostname labels rather than total rule count. Most-specific rules win; exact host specificity breaks a same-depth tie; ALLOW wins a remaining tie.

RuleListParser accepts first-party lines in the form block example.com or allow safe.example.com. It ignores comments and blank lines, normalizes entries, ignores malformed entries, deduplicates action/hostname pairs, and has a fixed maximum rule count. The bundled starter list is small and first-party; it is not derived from a third-party list and is not enabled by the app.

## DNS wire and upstream components

DnsWireCodec parses one-question DNS messages with bounds checks, validates name compression pointers and resource record lengths, and preserves transaction IDs and questions. The policy processor supports IN A and AAAA queries. Unsupported record types return NOTIMP rather than being rewritten. Blocked names return NXDOMAIN; malformed messages with an ID receive FORMERR; upstream timeout, failure, or malformed/mismatched responses return SERVFAIL.

DnsOverTlsResolver uses numeric upstream addresses, TLS SNI and hostname verification, a protected-socket callback, length-prefixed DNS-over-TLS framing, bounded timeouts, and per-query socket cleanup. Cloudflare DoT endpoints are the defaults. Resolver construction is injectable and tests use fake resolvers; no Internet is required by JVM tests. The resolver is not instantiated by the app.

## Packet codecs

UdpIpPacketCodec parses and builds checksummed IPv4 and IPv6 UDP datagrams, walks a bounded set of IPv6 extension headers, and rejects malformed, fragmented, and unsupported packets. DnsTunPacketProcessor connects DNS UDP payload policy to packet reconstruction. It returns Unsupported for non-DNS traffic; it does not forward general traffic.

These pure JVM components are not connected to a TUN descriptor. Passing codec tests is not a claim of an operating VPN or complete IP forwarding.

## VPN policy and lifecycle

The user selected this safety policy: **keep VPN establishment disabled until complete IPv4 and IPv6 forwarding is implemented and tested**. IPv6 must not bypass the VPN, and it must not be deliberately dropped as a substitute for support.

VpnReleaseGate requires each normal-connectivity capability and safety property to be implemented and tested: IPv4/IPv6 TCP and UDP, QUIC over UDP in both families, UDP/TCP DNS interception in both families, DNS filtering, no port-53 bypass, protected egress sockets, return traffic, bounded flow state, validated ICMP failure/MTU behavior, cleanup, emergency stop, and automated tests. Internet ICMP echo forwarding is diagnostic and is not an independent gate requirement. All readiness values are false in this build.

AdBlockVpnService therefore does not configure routes and does not create a TUN. Start attempts transition STARTING -> ERROR, then service cleanup transitions through STOPPING -> STOPPED. STOP sends a service stop request. There is no boot receiver, always-on setting, or automatic start path.

The future tunnel must handle all routed IPv4/IPv6 TCP and UDP traffic, including QUIC datagrams and return traffic. ICMP echo may be unsupported, but it must not be answered locally as if the remote host replied. ICMP errors associated with protected outer sockets are handled by Android; the selected engine's inner IPv6 Packet Too Big and oversized UDP behavior must be validated before startup can be enabled. Protect upstream sockets from recursion and handle or explicitly reject unsupported traffic classes. No current VPN start route reaches establish().

## App UI

The TV-oriented screen shows Protection: OFF and explains that dual-stack forwarding is incomplete. Start is disabled. Stop is exposed as an emergency stop action. Live counters, settings, and an active status screen are not yet present because the service is inactive.

## Tests and CI

GitHub Actions runs the Gradle unit-test task, Android lint, debug APK build, unsigned release APK build, and verifies both APK files exist. Unit tests cover rule normalization/precedence, blocklist parsing, DNS A/AAAA parsing and response handling, timeout/error cases, IPv4/IPv6 UDP parsing and reconstruction, unsupported packet classes, and the VPN readiness gate.

No Android emulator or physical device test is currently configured. Android service lifecycle, VpnService consent and cancellation, actual TUN routing, TLS upstream behavior on a device, and TV remote/focus behavior require Android device testing. A green CI run proves compilation/tests/builds, not VPN operation.

## Traffic, privacy, and known limits

No network traffic is processed in the current app. The DoT implementation is dormant. If wired later, the default upstream is Cloudflare and users should be told that the resolver receives queried names. No query history, analytics, ad SDK, or telemetry is included. Tests use fake resolvers and do not require Internet.

The starter rules are not guaranteed to block ads. Server-side insertion, DRM media, encrypted DNS/application protocols, and ad/content domains sharing infrastructure limit filtering effectiveness. Never claim universal ad blocking.
