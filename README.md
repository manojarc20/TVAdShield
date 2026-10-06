# TVAdShield

TVAdShield is a safety-first Android/Google TV filtering research project.

## Current V1 status

V1 contains a pure JVM hostname rule engine, a standalone testable DNS policy component, and a VPN lifecycle state machine. The Android app does not currently filter device traffic. The DNS component has no packet parser, packet serializer, network transport, or production upstream resolver. The VPN service intentionally does not establish a tunnel and stops with an error state when started.

The project includes no bundled third-party blocklist. GitHub Actions runs JVM unit tests and builds a debug APK; passing CI does not mean VPN traffic filtering works.

## Safety

TVAdShield does not root or unlock a television, flash firmware, modify system partitions or the operating system, or use ADB in CI. No TV or device is required for the current tests. Real-TV testing is postponed until packet transport and lifecycle recovery are implemented and separately reviewed.

## Filtering behavior

Rules support BLOCK and ALLOW, exact-host or subdomain matching, case and IDN normalization, and a deterministic most-specific-rule-wins policy. Invalid hostnames do not match rules. The DNS policy layer returns NXDOMAIN for blocked names, FORMERR for malformed input, and SERVFAIL for resolver errors/timeouts. Allowed queries are delegated to a mockable resolver interface; no real resolver is connected yet.

Universal ad blocking is not guaranteed. Server-side ads, DRM-protected media, encrypted protocols, and shared ad/content infrastructure may not be filterable without breaking playback.
