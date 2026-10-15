# Changelog

## [0.1.0] - Initial public release

- Extract the signed Access-to-HA session boundary into a reusable standalone integration and Go gateway.
- Add explicit trust configuration, contract v1, generic embedded demo and a thin adapter API.
- Add durable used-assertion tombstones, bounded credentials/connections, fixed route/header allowlists and isolated security tests.
- Permit signed top-level dashboard navigation from external links and identity-provider redirects; keep cross-site API, iframe and write rejection.
- Keep scheduled assertion expiry on the HA event loop and cancel pending expiry timers after manual revocation. This fixes a reproduced HA 2026.10.0 thread-safety failure during refresh-token removal.
- Add an optional network-disabled real-HA canary for setup, auth/storage, logout, restart and natural expiry.
- Include YAML/JSON installation examples in the integration ZIP and document staged installation, rollback, precise compatibility evidence and release qualification limits. No live cloud qualification or independent audit is claimed.

### Upgrade

Install the versioned integration ZIP and matching gateway from the same release. Configure an explicit issuer, application audience, origin and mapped Home Assistant administrator before enabling access. Back up the previous integration folder and configuration before replacing them; retain the previous release for rollback. The v1 contract accepts assertions lasting at most 24 hours and caps connections at five minutes.

### Security

Only validated signed assertions can request the mapped short-lived HA credential. Used assertion hashes persist across restarts and logout; obtain a fresh Access assertion after either event. Trusted-network admission is disabled by default. No site credentials or household configuration are included. This release is not an independent security audit or a claim of compatibility with every identity-provider configuration.
