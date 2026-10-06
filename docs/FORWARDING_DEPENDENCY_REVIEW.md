# Forwarding Dependency Review

Reviewed 2026-10-06 for the final release-candidate investigation. This review does not enable VPN startup. No third-party forwarding dependency is integrated in the app.

## Requirements used

A usable choice must work behind Android `VpnService`, process the TUN interface without root, handle IPv4 and IPv6 TCP/UDP with return traffic and bounded state, provide a safe way to intercept DNS, and have a license that can be adopted by this project. ICMP and ICMPv6 behavior must be explicit. A library that needs a local proxy also requires that proxy's sockets to be protected with `VpnService.protect()` to avoid routing loops.

## Candidates

| Candidate | License and Android fit | Capabilities and integration limits | Decision |
| --- | --- | --- | --- |
| [HEV socks5 tunnel](https://github.com/heiher/hev-socks5-tunnel), release [2.18.0](https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.18.0) | MIT; includes an Android JNI/AAR interface and Android ABI binaries. The tagged Android NDK configuration uses `APP_PLATFORM := android-29`, while this app currently supports API 24. | Documents IPv4/IPv6 TCP and UDP tunnel handling through a SOCKS5 server. UDP supports relay modes. It is a tun-to-SOCKS engine, not a direct Internet socket forwarder or DNS filter: a local SOCKS5 service is still needed, including protected TCP/UDP egress and DNS policy integration. Its ICMP option is `off` or local echo `reply`, not general ICMP/ICMPv6 forwarding. | Best Android-oriented core to prototype, but not yet proven suitable for the whole release contract. API 24 compatibility and ICMP/ICMPv6 behavior are open validation gates. Do not enable the VPN based on this dependency alone. |
| [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) | MIT; cross-platform, with a Go/gVisor-based stack. No equivalent Android `VpnService` integration is supplied as a turnkey app component. | IPv4/IPv6 and TCP/UDP are part of its proxy-oriented design. Still needs an upstream proxy and Android lifecycle/socket-protection integration. DNS policy and ICMP semantics need integration-specific verification. | Viable research alternative, but more Android glue and packaging work than HEV. |
| [sing-box Android](https://github.com/SagerNet/sing-box/blob/testing/docs/clients/android/features.md) | GPL-3.0-or-later; mature Android frontend/library, but adopting it carries GPL distribution obligations that need an explicit project licensing decision. | Offers Android TUN routing and a broad network stack. Its documented bridge outbound requires privileges/root on Android, so that mode is not suitable here. | Not selected for this app as-is: licensing and mode-specific root requirements are material constraints. A future adoption needs explicit license review. |
| [eycorsican/go-tun2socks](https://github.com/eycorsican/go-tun2socks) | MIT, but the repository is archived. | Older Go tunnel implementation; maintenance status is unsuitable for a new security-sensitive forwarding path. | Rejected as unmaintained. |

HEV's bundled subcomponents must also retain their own notices if its source is integrated: the reviewed dependency metadata identifies MIT licenses for `hev-task-system`, `yaml`, and `hev-socks5-core`, and BSD-3-Clause for `lwip`. The exact pinned source revisions and license files must be recorded and verified before vendoring or building them.

## Current decision and next proof

HEV is a candidate, not an approved complete forwarding solution. Before integration can be considered, a code review and host-side test harness must demonstrate:

1. The pinned Android binary works at the app's supported minimum API, or the dependency is rebuilt from pinned source for that API and validated.
2. TCP CONNECT and UDP ASSOCIATE work through a local bounded SOCKS5 service whose upstream sockets are protected from the VPN.
3. UDP flow mapping, return packets, timeouts, cancellation, and cleanup remain bounded and correct for both address families.
4. UDP and TCP DNS reach the existing filtering policy before upstream resolution; neither IPv4 nor IPv6 DNS can escape directly. Failure responses remain NXDOMAIN, FORMERR, or SERVFAIL as specified by the DNS layer.
5. IPv4/IPv6 ICMP behavior, including ICMPv6 errors needed for path MTU and network operation, is understood and tested. A local echo reply does not count as general ICMP forwarding.
6. Android instrumentation/emulator checks validate service startup, TUN ownership, protected sockets, stop, and fatal-error cleanup. Physical TV testing remains postponed.

If these conditions cannot be met with the dependency, the project must evaluate a different maintained user-space stack or implement the missing behavior. It must not weaken IPv6 policy or activate a partial tunnel to meet a schedule.

## Status

No dependency is currently added or invoked. The app has no live packet loop. The detailed readiness gate remains false for every capability; `VpnService.Builder.establish()` remains absent. The VPN stays disabled.
