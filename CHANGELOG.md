# Changelog

## [0.1.0] - Initial public beta

- Extract the signed Access-to-HA session boundary into a reusable standalone integration and Go gateway.
- Add explicit trust configuration, contract v1, generic embedded demo and a thin adapter API.
- Add durable used-assertion tombstones, bounded credentials/connections, fixed route/header allowlists and isolated security tests.
- Initial beta: one mapped administrator; no live HA/cloud qualification or independent audit claimed.

### Upgrade

Install the versioned integration ZIP and matching gateway from the same beta release. Configure an explicit issuer, application audience, origin and mapped Home Assistant administrator before enabling access. Back up the previous integration folder and configuration before replacing them; retain the previous release for rollback. The v1 contract accepts assertions lasting at most 24 hours and caps connections at five minutes.

### Security

Only validated signed assertions can request the mapped short-lived HA credential. Used assertion hashes persist across restarts and logout; obtain a fresh Access assertion after either event. Trusted-network admission is disabled by default. No site credentials or household configuration are included. This beta is not an independent security audit or a claim of compatibility with every identity-provider configuration.
