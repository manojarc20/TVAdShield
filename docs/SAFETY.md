# TVAdShield Safety Rules

Safety is a release gate. **The VPN is disabled in this build, and physical TV testing is not ready.**

## Dual-stack policy

The selected policy is to keep VPN establishment disabled until complete IPv4 and IPv6 forwarding is implemented and tested. Do not route IPv6 outside the VPN while claiming protection. Do not intentionally drop IPv6 traffic to simulate support. Do not establish a partial tunnel.

VpnReleaseGate requires tested IPv4 forwarding, tested IPv6 forwarding, and tested non-DNS forwarding. All are false. AdBlockVpnService does not configure routes and contains no TUN establishment call. A start request enters STARTING, then ERROR, and the service stops; destruction returns through STOPPING to STOPPED. The app UI says OFF and disables Start.

A future implementation must forward the full traffic contract safely before enabling the gate. DNS-only processing is insufficient because ordinary TCP/UDP/ICMP traffic and IPv6 must continue to work without bypassing the VPN. Unhandled or unsupported traffic must never be silently black-holed.

## Device and system restrictions

TVAdShield must remain a normal Android application using the official Android VPN framework. It must never root or unlock the TV, change bootloader/firmware/kernel/system partitions, modify Google TV files, or run ADB/device shell commands. No boot receiver or automatic VPN startup is present. This repository and CI do not install APKs on a device.

When a future VPN is operating, STOP must cancel workers, close upstream sockets and TUN descriptors, and reach STOPPED. Fatal errors must also tear it down. Android owns restoration of its prior network routing after a VPN service stops or is uninstalled; device behavior still requires testing on supported Android/Google TV versions.

## Current DNS and packet failure behavior

In the isolated policy layer, malformed DNS with a transaction ID receives FORMERR; unsupported query types receive NOTIMP; blocked names receive NXDOMAIN; resolver errors, timeouts, or malformed/mismatched upstream replies receive SERVFAIL. The DoT client verifies TLS hostname identity, uses bounded timeouts, and closes per-query sockets. It is not connected to the app.

The pure packet bridge accepts supported UDP DNS only and reports other protocols as Unsupported. It is not connected to a TUN, so it cannot drop real device traffic. A future live packet loop must forward or explicitly reject every class before VPN activation.

## Privacy

There is no analytics, advertising SDK, telemetry, cloud history, or persistent DNS query log. DNS statistics are not implemented. The dormant DoT resolver defaults to Cloudflare endpoints; if activated later, the upstream resolver will receive DNS names. Document that behavior and let users configure it before activation.

## Testing and readiness

Automated JVM tests and GitHub-hosted builds do not test Android VpnService consent, TUN routing, actual dual-stack forwarding, TV remote focus, or recovery after Android stops the service. No emulator or physical TV testing has been performed. Do not call this a release candidate ready for installation until the VPN gate can be enabled only after these traffic paths are fully implemented and tested.

Real-TV testing remains postponed because a partial VPN can disrupt connectivity and would not demonstrate that unsupported IPv6 or non-DNS traffic is handled correctly. Normal app uninstall must not alter TV system files. No universal ad-blocking claim is permitted.
