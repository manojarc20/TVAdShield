# TVAdShield V1 Architecture

Android TV app
- UI / settings
- Pure filtering core
- VpnService (not active in 0.1.0)
- DNS interception (planned)
- diagnostics (planned)
- statistics (planned)

Development order:
1. Pure filtering core
2. Automated tests
3. DNS resolver/interceptor
4. VPN packet transport
5. UI controls and lifecycle
6. Blocklist ingestion
7. Performance testing
8. Release candidate
9. Real TV testing

The filtering core is kept independent of Android networking so correctness can be tested before touching the television.
