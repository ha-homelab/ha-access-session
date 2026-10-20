# Changelog

## Unreleased

- Accept genuinely empty session requests with chunked HTTP/1 framing or an unknown HTTP/2 content length. Both the gateway and HA adapter now verify the decoded body with a one-byte read and a two-second deadline; nonempty bodies, read failures and stalled requests remain rejected. The gateway normalizes verified empty requests before proxying them to HA.
- Add a default-off canonical media-player artwork GET route with separate HA bearer authentication, same-origin request checks, a 10-second ceiling and unconditional redirect rejection. Existing Access admission, identity mapping and revocation checks remain required.

## [0.1.2] - 2026-10-18

### Changed

- Restore Dependabot approval automation by routing default-branch dependency PR metadata through the trusted target workflow. Trusted-author, draft and opt-in label checks remain enforced; the approval job does not execute PR code.
- Synchronize package version fields for this CI maintenance release.

### Upgrade

Update the integration and gateway together from the verified release. Retain private trust and TLS configuration and the previous matching pair for rollback.

### Security

Revocation freshness, replay protection and signing-key floors remain in force. Offline qualification does not establish acceptance by a live identity provider.

## [0.1.1] - 2026-10-17

### Changed

- Require native Linux amd64 and arm64 smoke checks of the exact staged gateway archives, with source-bound hash receipts, before release publication.

- Prevent stale session replies from undoing revocation.
- Align RSA signing-key strength checks across Go and Python verifiers and require Go 1.27.2 for new builds.
- Add an optional native HTTPS gateway listener and use qualified canonical clients for signed release publication.

### Upgrade

Update the integration and gateway together from the verified release. Existing HTTP behind a trusted edge remains available; native HTTPS requires explicitly supplied certificate and key files. Review configured signing and TLS keys against the documented minimum sizes. Preserve private configuration and the previous matching pair for rollback.

### Security

Owned HTTPS clients verify exact certificate-key sizes before HTTP requests. Weak configured gateway certificates are rejected before opening a listener, and signing keys must meet the shared RSA-2048 floor. Loopback and synthetic Home Assistant tests do not replace live identity-provider or installation qualification.

## [0.1.0] - Initial public release

- Extract the signed Access-to-HA session boundary into a reusable standalone integration and Go gateway.
- Add explicit trust configuration, contract v1, generic embedded demo and a thin adapter API.
- Add durable used-assertion tombstones, bounded credentials/connections, fixed route/header allowlists and isolated security tests.
- Permit signed top-level dashboard navigation from external links and identity-provider redirects; keep cross-site API, iframe and write rejection.
- Keep scheduled assertion expiry on the HA event loop and cancel pending expiry timers after manual revocation. This fixes a reproduced HA 2026.10.0 thread-safety failure during refresh-token removal.
- Require the network-disabled real-HA canary in CI for source and packaged integration setup, auth/storage, logout, restart and natural expiry; retain local opt-in through `HA_PYTHON`.
- Include YAML/JSON installation examples in the integration ZIP and document staged installation, rollback, precise compatibility evidence and release qualification limits. No live cloud qualification or independent audit is claimed.

### Upgrade

Install the versioned integration ZIP and matching gateway from the same release. Configure an explicit issuer, application audience, origin and mapped Home Assistant administrator before enabling access. Back up the previous integration folder and configuration before replacing them; retain the previous release for rollback. The v1 contract accepts assertions lasting at most 24 hours and caps connections at five minutes.

### Security

Only validated signed assertions can request the mapped short-lived HA credential. Used assertion hashes persist across restarts and logout; obtain a fresh Access assertion after either event. Trusted-network admission is disabled by default. No site credentials or household configuration are included. This release is not an independent security audit or a claim of compatibility with every identity-provider configuration.
