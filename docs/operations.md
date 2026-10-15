# Configuration and troubleshooting

## Shared settings

`issuer` and `origin` are full HTTPS origins without a trailing slash, user information, query or fragment. The issuer selects the fixed `/cdn-cgi/access/certs` endpoint. `audience` is the exact dedicated Access application's audience; `email` is matched case-sensitively. The HA `user_id` is an explicit 32-character lower-case hexadecimal account ID. No account is discovered or created automatically.

`allow_trusted_network` defaults false. `max_assertion_lifetime_seconds` defaults 86,400, cannot exceed that maximum, and must match in both components. `token_lifetime_seconds` is HA-only, defaults 300 and accepts 1–300. `max_connection_seconds` is gateway-only, defaults 300 and accepts 1–300. `max_sessions` is HA-only and accepts 1–128, default 32. Reducing token lifetime does not change the independent connection ceiling; configure both to suit your policy.

Gateway `upstream` is a single origin, with no path/user information/query/fragment. HTTPS is required unless `allow_insecure_upstream` is explicitly true for an isolated network. This setting does not disable certificate verification. `static_dir` replaces embedded files at startup; otherwise the synthetic demo is served. The CLI defaults to loopback HTTP on `127.0.0.1:8080`; TLS is terminated by your trusted edge. Bind a different interface only when protected by the intended network boundary.

`session_path` is an optional gateway compatibility-adapter route below `/api/`. The standalone HA integration always uses `/api/ha_access_session/v1/session`; do not change the gateway field unless you have deliberately installed a corresponding adapter.

## Troubleshooting

**401 before loading the page:** verify the edge supplies exactly one signed assertion for the dedicated application. Compare issuer/audience and synchronize clocks. A cookie, plain email header or IP header is insufficient. Do not paste JWTs into online decoders or issues.

**403:** verify the exact public Host and HTTPS Origin and exact mapped email. In HA, verify the configured ID is an active, non-local-only, non-system-generated administrator. Non-admin support is intentionally absent in this beta.

**401 after logout or HA restart:** expected. Obtain a fresh assertion by signing out of the dedicated Access application and signing back in. Reusing a still-cached assertion cannot recreate its old session.

**429:** too many distinct assertions remain unexpired. The default HA cap includes revoked/used assertion hashes until their original expiry; waiting for expiry releases capacity. Do not delete the revocation store. Inspect whether a client is repeatedly forcing new Access logins.

**502/503:** check gateway-to-HA connectivity, server certificate trust, key-service availability and HA storage permissions. The service deliberately rejects redirects at both the key-fetch and proxy boundaries. Fix the configured final endpoint rather than weakening verification.

**404 on a REST API, `/auth/*`, or a query-string asset:** expected under v1's route contract. Use the explicit exchange and HA WebSocket. Query-based cache busting is unsupported; use content-hashed asset filenames if needed.

**WebSocket reconnects:** expected at the configured maximum connection age, even if the Access session lasts longer. Obtain/reuse an unexpired short token through the exchange and reconnect. The demo does not perform device operations or open a WebSocket.

## Updates and removal

Install matching component versions and retain HA's revocation storage across updates. Keep issuer/origin/client ID stable. Before changing the origin or removing the integration, revoke its managed `HA Access Session` refresh tokens in the HA profile or an administrator-controlled HA maintenance procedure. Stop the gateway before changing trust settings. Removing a component or changing the client ID cannot retroactively discover tokens stored under a former client ID.

Do not configure request/response logging to capture assertion headers, HA token bodies or WebSocket authentication messages. Gateway error logs intentionally contain no request URLs, claims, tokens or backend bodies. Synthetic examples are suitable for bug reports after confirming they contain no real configuration.

## Optional HA login compatibility

`enable_ha_login` defaults false. Existing private dashboards may set it true to retain an explicit normal HA OAuth login fallback. It permits GET `/auth/authorize` with `response_type=code`, client ID and redirect URI equal to the configured origin plus `/`, and a nonempty bounded state. It also permits GET `/auth/providers`; POST `/auth/token`, `/auth/revoke`, `/auth/login_flow`; GET/POST `/auth/login_flow/<32-hex-flow-id>`; and read-only `/frontend_latest/`, `/frontend_es5/`, `/static/`, `/translations/`, `/manifest.json`, `/favicon.ico`. It does not allow arbitrary `/auth/*` paths. OAuth request bodies are capped at 64 KiB. Every route still requires a verified Access assertion; POSTs require the exact Origin. Assertions and proxy identity headers are never forwarded to these login routes.

The root static page may then receive only `code` and `state` query parameters. Upstream HTTP redirects are accepted only to that exact HTTPS origin/root with those two parameters; other redirects remain blocked. Normal HA OAuth issues its own refresh credentials and chooses an account through HA authentication, distinct from the v1 mapped session exchange. Any browser storage for this legacy fallback is the consuming frontend's responsibility. The explicit v1 session exchange continues to return no refresh credential.

`content_security_policy` can override the default static-page CSP for a trusted existing frontend. New dashboards should keep the restrictive default. Only an administrator may set this; permissive inline/blob/frame policies enlarge the frontend trust surface. Embedded Go consumers can supply `Config.StaticFS` instead of `static_dir`; the same static file checks apply.
