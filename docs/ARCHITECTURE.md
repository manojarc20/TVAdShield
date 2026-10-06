# TVAdShield V1 Architecture

## What V1 does

V1 provides a platform-independent hostname rule engine, a testable DNS policy component, and an explicit VPN lifecycle state machine. The Android app does not yet apply filtering to device traffic. The DNS component is a policy layer, not a DNS packet parser, serializer, network server, or upstream resolver.

No third-party blocklist is bundled. Rules must be supplied by a future caller.

## Filtering core

The rule engine depends only on the JVM. Hostnames are trimmed, converted to lowercase ASCII using IDN punycode, and may have one trailing DNS root dot. Invalid names and invalid rule patterns are rejected. Matching uses label boundaries, so a rule for ads.example.com cannot match notads.example.com.

A rule can match the exact host only or the exact host plus subdomains. The most specific matching rule wins; equal-specificity ALLOW rules win ties. With no matching rule, the core returns ALLOW. This policy is deterministic and covered by JVM unit tests.

## DNS policy component

DnsFilteringComponent accepts a hostname query, validates and normalizes the hostname, checks the rule engine, and either returns a policy response or calls an injected DnsResolver with the normalized hostname and timeout budget. The resolver is a mockable interface. There is no production resolver and no VPN packet integration.

- A blocked hostname returns NXDOMAIN and is not sent to the resolver.
- Malformed input returns FORMERR and is not sent to the resolver.
- An allowed hostname is passed to the resolver and its response is returned.
- A resolver timeout or exception returns SERVFAIL.

Resolver failures are explicit. The component does not silently fall back to an unfiltered resolver (fail open) or fabricate NXDOMAIN for an allowed host (fail closed). Its timeout is a budget passed to the resolver; any future resolver adapter must enforce it. DNS packet parsing, serialization, retries, and transport remain unimplemented.

## VPN lifecycle and boundaries

AdBlockVpnService owns only the Android service lifecycle gate. VpnStateMachine is a pure JVM state machine with STOPPED, STARTING, RUNNING, STOPPING, and ERROR states. The current service receives a start request, transitions to STARTING then ERROR because packet transport is absent, and stops. It does not call VpnService.Builder.establish().

Packet transport, DNS processing, rule evaluation, statistics, and UI state are separate concerns. No packet transport, statistics pipeline, or UI state binding is implemented. RUNNING is only a modeled state; the service cannot enter it in the current V1.

## Testing strategy

GitHub Actions runs the complete Gradle unit-test task and assembles a debug APK on every push and pull request. JVM tests cover hostname normalization and rule precedence, DNS policy responses and resolver errors/timeouts, and VPN state transitions. These tests require no Android device and do not demonstrate packet-level or VPN functionality. The CI build is a packaging check, not a claim that filtering is active.
