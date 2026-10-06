# TVAdShield

TVAdShield is a safety-first Android/Google TV filtering project. This build is a **development candidate, not ready for physical TV testing**.

## Current behavior

- The main screen reports Protection: OFF.
- The Start control is disabled.
- The Android VPN service deliberately does not create a VPN interface. It moves a start attempt through STARTING to ERROR and stops.
- Rule parsing, hostname matching, DNS wire processing, DNS-over-TLS client code, and IPv4/IPv6 UDP packet codecs are isolated and covered by JVM tests.
- Those components are not connected to a TUN packet loop. No traffic is currently filtered or sent to an upstream resolver.
- A small first-party starter rule file is included. It is not a third-party list and is not active in the UI.

The VPN will remain disabled until complete IPv4 and IPv6 forwarding, DNS and non-DNS traffic behavior, resource cleanup, and automated tests are all implemented and reviewed. IPv6 will not be passed around the VPN or intentionally dropped as a shortcut.

## Safety and privacy

TVAdShield does not root or unlock a TV, modify firmware, system partitions, kernel, bootloader, or Google TV OS, or use ADB. CI builds and tests on GitHub-hosted Ubuntu; it does not install an APK on a device. There is no boot receiver or automatic VPN startup.

No analytics, advertising SDK, telemetry, or DNS history storage is included. The DoT resolver code is not instantiated by the app, so this build sends no DNS queries through that resolver. If wired in later, the current DoT defaults are Cloudflare endpoints and DNS queries would be visible to that upstream according to its service terms.

## Development and validation

The repository uses Gradle 8.9, JDK 17, and Android SDK API 35. GitHub Actions runs JVM unit tests, Android lint, debug APK assembly, and unsigned release APK assembly on every push and pull request. CI success does not mean the VPN or filtering is active.

Build locally with:

- ./gradlew test
- ./gradlew lint
- ./gradlew assembleDebug
- ./gradlew assembleRelease

The release APK is unsigned; no signing key is included. Tests cover JVM logic only. IPv4/IPv6 packet handling, DoT against a real upstream, VPN lifecycle behavior on Android, Android emulator behavior, and physical TV behavior remain unverified. Physical TV testing is not ready.

## Limitations

The packet bridge supports unfragmented UDP DNS packets in its pure JVM layer. Unsupported traffic is reported as unsupported; it is not silently claimed to be forwarded. IPv6 parsing tests do not demonstrate full IPv6 forwarding. The app cannot yet filter device traffic, provide live statistics, configure upstream servers in a settings screen, or guarantee ad removal.

Universal ad blocking is not possible to promise. Server-side ads, DRM-protected media, encrypted protocols, and shared ad/content infrastructure may not be filterable without breaking playback.

## Installation and recovery

Do not install this development candidate on a TV. Once a future candidate has passed dual-stack device-independent checks and is explicitly ready for device testing, use Android's normal app installation and VPN consent flows only. To stop a future active VPN, use the app's Stop control or Android VPN settings; uninstalling a normal app removes its VPN service and does not modify system networking files. This current build never establishes a VPN.
