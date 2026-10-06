# TVAdShield Safety Rules

Safety is a release gate. V1 is not authorized to change device networking.

## Current safeguards

- The app does not connect to, control, root, unlock, flash, or modify a television.
- No ADB workflow or device installation is part of CI.
- AdBlockVpnService intentionally never calls VpnService.Builder.establish(). A start request enters STARTING, then ERROR because packet transport is not implemented, and the service stops.
- No production VPN tunnel, DNS packet transport, real upstream resolver, third-party blocklist, or filtering UI is wired into the app.
- Unit tests and the debug APK build run on GitHub-hosted Ubuntu and do not require a TV.

## DNS policy failure behavior

A matching blocked name receives NXDOMAIN by design. Malformed query names receive FORMERR. An allowed name is delegated to the resolver abstraction. A timeout or resolver exception produces SERVFAIL; the component does not bypass filtering with a fallback resolver and does not silently turn an upstream failure into NXDOMAIN. This makes failures explicit to a future caller. A concrete resolver must enforce the timeout budget passed to it.

## Why TV testing is postponed

TV testing is postponed until packet parsing and forwarding, DNS transport, service lifecycle recovery, start/stop behavior, and failure handling exist and have automated coverage. Connecting a device before those pieces are implemented could interrupt its network access and would not validate this policy-only prototype. Future device testing must be a separately reviewed, explicit stage.

## Limits

Network filtering cannot guarantee removal of every ad. Server-side insertion, DRM-protected media, encrypted protocols, and ads delivered from the same infrastructure as content can require different techniques or may be impossible to filter without breaking playback. No effectiveness claim should be made without measured testing.
