# Contract v1

Release version and contract version are distinct. The gateway, integration and reference demo in a release must be installed together. Additive JSON response fields may appear in v1; clients must reject incompatible `contract_version` values. Different routes, identity semantics or privilege models require another contract version.

## Identity

Both components require exactly one `Cf-Access-Jwt-Assertion` header, with length 1–16,384 characters. They verify RS256 against the configured issuer's HTTPS `/cdn-cgi/access/certs` endpoint and never follow a token-selected `jku`/`x5u`, issuer, redirect, or key URL. HA requires a signing RSA JWK with at least 2048 bits. Configure a Cloudflare Access issuer; the claim profile is not generic OIDC.

Required claims: exact `iss`, configured `aud` present as string or string array, nonempty `sub`, exact case-sensitive mapped `email`, `type: "app"`, integer positive `iat`, integer future `exp`. The assertion lifetime `exp - iat` must be positive and no longer than `max_assertion_lifetime_seconds` (default and hard maximum 86,400). `iat` must not be in the future. If `nbf` is present, it must be an integer no later than now. Synchronize system clocks; no future-time grace is applied.

The `common_name` claim must be absent, including null, for owner mapping. With explicit network opt-in in **both** components, the alternate profile is `sub: ""`, with both `email` and `common_name` absent, retaining every other signature and claim requirement. Request IPs and unsigned forwarded identity headers are never identity evidence.

## Browser boundary

Host must match the configured HTTPS origin host, including any explicit port. An Origin header, when present, must match that full origin exactly. All cross-site fetch requests are rejected. Session exchange and WebSocket upgrade require exactly one matching Origin. No CORS endpoint is provided. Requests cannot select an upstream, key endpoint, user, scope or return URL.

The gateway rejects noncanonical/encoded paths, unapproved methods, unexpected query parameters and nonempty exchange bodies. The HA integration independently rejects nonempty exchange bodies and any query except one `revoke=1`. Static assets and `/session` have no query parameters in v1.

## Exchange

`POST /session/ha`, empty body. The gateway strips credentials and identity headers, then forwards only the verified assertion and configured origin to `POST /api/ha_access_session/v1/session`. HA verifies the signature again and checks the configured account is active, an administrator, not local-only and not system-generated.

A successful JSON response has `contract_version: 1`, `access_token` (opaque string), `expires_in` (integer, 1–300), `session_expires_at` (JWT expiry as Unix seconds). Every response is `Cache-Control: no-store`. The lifetime is the lesser of the configured token lifetime and remaining assertion lifetime minus one second. A refresh credential never leaves HA.

HA keys sessions by SHA-256 of the full assertion, serializes creation, caps active/unexpired used assertions at 32 by default (configurable 1–128), and persists an expiry tombstone before issuing a token. Repeated calls with the same active assertion reuse its server-held refresh token. HA validates that the refresh token still belongs to the configured account before reissue.

## Revoke and restart

`POST /session/ha?revoke=1`, empty body, returns 204 after HA persists the tombstone and deletes any associated refresh token. Revoking before initial exchange is also effective. The current gateway process blocks that assertion and cancels its active proxy connections after a successful HA response. HA profile revocation prevents token reissue on the next exchange.

On HA restart, startup removes refresh tokens belonging to this configured client ID and loads all used-assertion hashes as revoked. This intentionally requires a **new signed assertion**, obtained by signing out of Access and back in, rather than silently recreating an old session. Do not delete or restore an old `.storage/ha_access_session.used_assertions` file to bypass a logout.

Every proxied connection is capped at the earlier of assertion expiry or `max_connection_seconds` (default and hard maximum 300). An Access-provider logout is not a real-time revocation notification to this gateway. See the detailed limits in the security document.

## Errors

401: absent/invalid assertion, expired or revoked session. 403: unmapped identity/account, host/origin mismatch. 400: malformed direct HA exchange. 404: gateway route/method/query not allowed. 429: bounded session capacity exhausted. 503: HA key service or durable storage unavailable. 502: gateway upstream unavailable or redirect rejected. These do not reveal tokens, claims, user IDs or backend response bodies in gateway logs.
