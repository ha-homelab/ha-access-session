# Threat model and limits

## Authority and assumptions

The mapped HA administrator, HA host/storage, configured issuer and its signing keys, Access policy administrator, gateway binary/configuration, TLS terminators, and all served frontend scripts are trusted. A compromised item in this set can act with the mapped administrator's privileges. The integration does not narrow those privileges.

The adversary may send direct requests to the gateway or HA, forge unsigned headers, change host/origin/query/body/path, replay a still-valid stolen assertion, or attempt to select another account/upstream. Both verifiers require a valid signature and configured claims. Origin checks mitigate browser cross-site requests; they are not authentication for a non-browser client, which can choose its Origin header. A signed assertion is a bearer credential, so theft remains consequential.

HA's refresh token stays server-side and only a bounded access token reaches the browser. Requests cannot pick an account, scope, redirect or token destination. The gateway forwards assertions exclusively to the configured session endpoint. By default it exposes neither arbitrary REST APIs nor `/auth/*`; HA's WebSocket still enforces its own credential checks. Upstream redirects and cookies are blocked. Exchange state is bounded and serialized. Storage failure fails closed before issuing a token.

## Optional artwork boundary

The gateway's `enable_media_artwork` setting is default-off and independent of HA login compatibility. Enabling it admits only bodyless, queryless GETs to canonical `/api/media_player_proxy/media_player.<object_id>` paths with a bounded lowercase ASCII object ID and exactly one bounded Bearer authorization header. The signed Access assertion and mapped identity are still required, and HA independently authenticates and authorizes the bearer token. The route is not scoped to a frontend's saved inventory; any canonical media-player ID remains subject to that HA user's permissions. It grants no arbitrary URL, entity domain, REST endpoint or write method.

The exact configured Origin is required when supplied. Requests without it need `Sec-Fetch-Site: same-origin`; duplicate or other Fetch Metadata values are rejected. These browser request checks supplement credentials and are not authentication for non-browser clients. Only existing allowlisted HA request headers are forwarded; the assertion and proxy identity headers are stripped. All artwork redirects are rejected, including the otherwise permitted same-origin OAuth callback. The maximum request lifetime is 10 seconds, further limited by the assertion and connection deadlines, with in-flight cancellation on same-process session revocation. Responses are not cached by the gateway and have cookies/CORS headers stripped. The gateway streams HA's bytes; the frontend must bound downloads and decoded image dimensions and accept only its supported image formats.

## Explicit trusted-network admission

`allow_trusted_network: false` is the default in **both** components. Turning it on accepts a valid issuer-signed `type: app` assertion with an empty subject and absent email/common_name. It **maps this anonymous network assertion to the same full HA administrator**. There is no per-person attribution.

Use this only after understanding and isolating the issuer policy that signs those assertions, with a dedicated application and audience. An overly broad IP policy effectively grants HA administrator access to everyone admitted by it. Never enable it solely because a proxy supplies a particular IP header. It does not trust LAN addresses or `CF-Connecting-IP`; forged headers without a signature are rejected. The beta does not create or verify the correctness of an external network policy.

## Revocation behavior

- Exchange logout persists a tombstone, removes the refresh token and prevents rebootstrap with that assertion. It closes the assertion's sockets on the gateway process handling that logout.
- Deleting the managed refresh token through HA prevents further issuance. Existing WebSocket connections may remain authenticated until their bounded connection deadline; the gateway enforces at most 300 seconds.
- HA restart removes managed refresh tokens and treats every persisted used assertion as revoked. A new Access assertion is required. This prioritizes replay prevention over automatic reconnect after restart.
- Gateway memory is not a shared revocation database. Other gateway replicas may retain already-open sockets until their deadline; HA still rejects reissue after logout. Gateway restart drops sockets and resets its local tombstones, while HA durable tombstones remain authoritative for exchange.
- A copied already-issued HA access token is not origin-bound and can be presented directly to any reachable HA endpoint. `expires_in` describes the JWT's nominal expiry; HA 2026.10.0 accepts access-token expiry with up to ten seconds of clock leeway while its backing refresh token still exists. Assertion expiry removes that refresh token, and gateway connection limits are separate. Protect the HA network boundary. Directly established HA connections are outside the gateway's connection deadline.
- Logging out of Access alone does not notify this service or erase a still-valid signed JWT. Use the explicit exchange logout too. Assertion expiry bounds future admission, and the connection deadline bounds current gateway streams.

## Known limits

Development and CI use PyJWT 2.15.1, including its published security fixes.
The integration uses Home Assistant's installed PyJWT and aiohttp; it does not
replace HA's dependency constraints. Keep HA updated and review its dependency
advisories before deployment. This verifier accepts RS256 only, performs its own
bounded fixed-origin JWKS fetch without redirects, and rejects non-canonical
JWT segments before signature verification. Those controls do not certify other
integrations that share the host's dependencies.

Automated review and tests do not constitute an independent security audit or production certification. Tests use real RSA signatures and local HTTP/WebSocket servers. A separate network-disabled canary exercises real Home Assistant 2026.10.0 configuration, auth, storage and scheduled expiry in temporary state. No cloud Access account, browser SSO flow, reverse proxy, device or public deployment was exercised by that canary. See [compatibility evidence and release criteria](compatibility.md); changes to HA internal auth/storage APIs may require an adapter update.

No least-privilege token scopes, multi-user mapping, service-token admission, distributed instant logout, rate-limiting proxy, custom login UI, Access provisioning or automatic JWT renewal is included. Capacity limits are denial-of-service bounds, not a replacement for edge rate limits. The Go verifier's key cache follows go-oidc behavior; the HA verifier refreshes after five minutes and rate-limits unknown-key refreshes to thirty seconds once a valid keyset is cached. Removal of a cached signing key is not instantaneous revocation.

A malicious trusted frontend can use the returned administrator token. The CSP restricts asset and network sources but cannot make malicious same-origin JavaScript safe. Do not point `static_dir` at an application repository or a directory containing anything you do not intend to serve.

Durable tombstones contain only assertion SHA-256 hashes and expiries. They do not contain raw JWTs or refresh credentials. HA's own auth storage retains server-held credentials. Keep both stores private and backup/restore them consistently. Changing origin/client ID before cleaning up old managed tokens can leave old credentials until their original expiry or manual removal; follow operations guidance.

## Reporting

Do not include JWTs, cookies, HA tokens, real identities, internal addresses, or home configuration in public issues. Use [GitHub private vulnerability reporting](https://github.com/ha-homelab/ha-access-session/security/advisories/new) or alvit.work@gmail.com. For non-sensitive bugs, a synthetic configuration and failing isolated test are ideal.

## Transport and signing-key enforcement

Both verifiers accept RS256 signing keys only when the RSA modulus is at least 2048 bits. The Go issuer transport filters keys before go-oidc caches them. Owned HTTPS clients perform normal certificate/hostname verification and then require a complete verified chain, including its root, to meet the exact key-size minimum. Go may accept any fully strong verified alternative chain. See [the supported transport profile](tls-policy.md). This does not change the trust granted to the configured issuer or administrator.
