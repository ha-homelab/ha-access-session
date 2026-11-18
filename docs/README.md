# Documentation

Guides for the contract v1 session boundary that exchanges a verified Cloudflare Access
application JWT for a short-lived Home Assistant access token, plus the release
qualification, signing and transport evidence that surrounds it.

## Understand and deploy

- [Contract v1](contract-v1.md) — the identity claims, route shapes and compatibility rules shared by the gateway and integration.
- [Install, qualify and upgrade](installation.md) — the two components, the dedicated Access application and the single mapped administrator.
- [Configuration and troubleshooting](operations.md) — every shared, integration-only and gateway-only setting and the failures it produces.
- [Thin compatibility adapters](adapter-api.md) — using the versioned Python implementation from `custom_components.ha_access_session.access`.
- [Browser acceptance](browser-compatibility.md) — the required browser configurations and the loopback-only synthetic demo.
- [Compatibility evidence and release qualification](compatibility.md) — the checked Home Assistant, Python and frontend scope behind a stable tag.

## Trust and policy

- [Threat model and limits](security.md) — what is trusted, what the adversary may attempt, and which guarantees stop where.
- [HTTPS and signing-key policy](tls-policy.md) — the TLS floors and key-size requirements the issuer fetch and upstream transports enforce.
- [Release-candidate fuzz testing](fuzzing.md) — the Go targets, corpus, and when a mutation campaign is dispatched.

## Release operations

- [Verify a signed release](release-signatures.md) — checking the release manifest signature and the artifacts it covers.
- [Patched release signer and verifier](release-signer.md) — the downstream Cosign build, its CI export artifact and how to check the receipt.
- [Qualified GitHub CLI for release operations](release-github-cli.md) — the pinned `gh` build and what it is qualified for.
- [Verified release-client transport profile](release-tls-profile.md) — the transport settings a release client must use.
