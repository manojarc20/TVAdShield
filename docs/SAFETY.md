# TVAdShield Safety Rules

Safety is a release gate.

TVAdShield must never require root, bootloader unlocking, firmware flashing, custom firmware, system partition changes, or kernel changes.

The full-device VPN must not be enabled until packet forwarding, DNS handling, lifecycle recovery, explicit start/stop, crash recovery, and fail-safe behavior are implemented and tested.

If a future VPN build causes connectivity problems: stop TVAdShield, disconnect the VPN, uninstall if necessary, confirm normal Google TV connectivity, and stop testing until the cause is understood.

Network filtering cannot guarantee removal of every ad. Server-side ad insertion, DRM-protected media, encrypted protocols, and ads delivered from the same infrastructure as content can require different techniques or may be impossible to filter without breaking playback.
