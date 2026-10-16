# Compatibility evidence and release qualification

Contract v1 and the release channel describe different things. A stable tag does not certify every Home Assistant version, Cloudflare policy, reverse proxy or frontend. This component uses HA's internal auth/storage APIs, so a successful test on one version is evidence for that version only.

## Checked scope

On 2026-10-15, the isolated lifecycle canary was run with **Home Assistant 2026.10.0 and Python 3.14.7**. It uses real configuration validation, component setup, an unbound HA HTTP server/router, AuthManager, user and token objects, Store persistence and scheduled callbacks. All files are temporary and socket connections, binds and DNS are blocked. Dependency startup is replaced so no running HA service, integration discovery, device or cloud account is used.

The canary checks that:

- YAML is accepted for valid settings and classified as a configuration error for invalid bounds.
- The real HTTP router registers the session POST endpoint.
- A locally signed synthetic assertion issues a bounded HA token that the real AuthManager validates for the configured account.
- Logout invalidates that token and denies reuse of the assertion.
- Natural assertion expiry removes the refresh token on the HA event loop and invalidates the HA token.
- Used-assertion state persists, and setup after a simulated process restart removes managed tokens and rejects replay.

This check reproduced a pre-release defect: an undecorated timer listener ran refresh-token removal in an executor thread and raised a thread-safety error during HA's storage scheduling. The listener now runs as an HA callback on the event loop. Mock-only tests had not detected this. The owned `Offline contract tests` workflow now requires the canary for both source and the built integration ZIP on Python 3.14, within its 15-minute job limit. It installs Home Assistant 2026.10.0 in a separate `.ha-test` virtual environment so the development lock cannot override HA's dependency constraints.

The ordinary suite independently tests real RSA/JWT verification, mocked HA edge cases and loopback Go HTTP/WebSocket behavior, including origin/path/header restrictions, revocation, bounded connections and key-service failures. Run it with race detection and vet through `scripts/check.sh`. The current minimum and qualified toolchain is Go 1.27.2, as declared in `go.mod`.

No live Cloudflare SSO, public reverse proxy, production HA deployment, physical device, HA OS add-on packaging or complete optional HA OAuth fallback was qualified by these checks. No compatibility range beyond the named HA version is claimed. The project is a custom integration plus a standalone Linux gateway, not an HA-endorsed integration or an independently certified security product.

## Repeat the real-HA canary

Use a separate environment for the target HA version. The pinned development lock supplies mock-test dependencies; it intentionally does not replace HA's own dependency constraints. For example, with a Python version supported by the target HA release:

```sh
python3 -m venv .ha-test
.ha-test/bin/python3 -m pip install 'homeassistant==2026.10.0'
.ha-test/bin/python3 -I tests/real_ha_lifecycle.py
```

Installing packages requires registry access. The canary itself rejects network operations and uses no real credentials. It runs separately because `tests/test_access.py` installs lightweight HA stubs in its interpreter. Do not combine those modules in one test discovery process.

To run ordinary checks and the real-HA canary together after preparing both environments:

```sh
HA_PYTHON="$PWD/.ha-test/bin/python3" ./scripts/check.sh
```

A failure after an HA update is a release blocker for claiming that version. Preserve the version and redacted traceback, reproduce it in temporary state, and update the adapter/tests before widening the documented scope.

## RC and stable acceptance

Before publishing a release candidate, run the normal suite and this canary on its source, build the component pair, and verify archive layout and signature metadata. Run the lifecycle canary against the integration extracted from the candidate archive as well, so source-only success cannot hide packaging differences. After verification and staging, run:

```sh
.ha-test/bin/python3 -I tests/real_ha_lifecycle.py --component-root /path/to/extracted-integration
```

That directory must contain `custom_components/ha_access_session`; the canary verifies it imports the staged component. Verify that the gateway archive matches its advertised architecture and version metadata.

Before stable promotion, repeat the candidate's relevant checks and confirm the signed source/asset identities. Stable promotion reuses candidate bytes under the repository's release policy; an embedded base version alone cannot distinguish RC from stable. Keep an explicit record of tests passed, tests not performed and the exact candidate source SHA. A deployment should complete the [operator acceptance steps](installation.md#acceptance-without-device-commands) before relying on it for a real home.
