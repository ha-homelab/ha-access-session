# Configuration and troubleshooting

## Shared settings

`issuer` and `origin` are full HTTPS origins without a trailing slash, user information, query or fragment. The issuer selects the fixed `/cdn-cgi/access/certs` endpoint. `audience` is the exact dedicated Access application's audience; `email` is matched case-sensitively. The HA `user_id` is an explicit 32-character lower-case hexadecimal account ID. No account is discovered or created automatically.

`allow_trusted_network` defaults false. `max_assertion_lifetime_seconds` defaults 86,400, cannot exceed that maximum, and must match in both components. `token_lifetime_seconds` is HA-only, defaults 300 and accepts 1–300. `max_connection_seconds` is gateway-only, defaults 300 and accepts 1–300. `max_sessions` is HA-only and accepts 1–128, default 32. Reducing token lifetime does not change the independent connection ceiling; configure both to suit your policy.

Gateway `upstream` is a single origin, with no path/user information/query/fragment. HTTPS is required unless `allow_insecure_upstream` is explicitly true for an isolated network. This setting does not disable certificate verification. `static_dir` replaces embedded files at startup; otherwise the synthetic demo is served. The CLI defaults to loopback HTTP on `127.0.0.1:8080`; TLS is terminated by your trusted edge. Bind a different interface only when protected by the intended network boundary.

`session_path` is an optional gateway compatibility-adapter route below `/api/`. The standalone HA integration always uses `/api/ha_access_session/v1/session`; do not change the gateway field unless you have deliberately installed a corresponding adapter.

## Troubleshooting

**Integration not found / YAML rejected:** check that the installed path is exactly `custom_components/ha_access_session/manifest.json`, with no doubled directory, and restart HA. Supply the YAML block as a mapping, not a list. Booleans must be YAML booleans and lifetimes must be integers. HA logs should classify invalid settings as a configuration validation error.

**401 before loading the page:** verify the edge supplies exactly one signed assertion for the dedicated application. Compare issuer/audience and synchronize clocks. A cookie, plain email header or IP header is insufficient. Do not paste JWTs into online decoders or issues.

**403:** verify the exact public Host and HTTPS Origin and exact mapped email. In HA, verify the configured ID is an active, non-local-only, non-system-generated administrator. Non-admin support is intentionally absent in v1.

**401 after logout or HA restart:** expected. Obtain a fresh assertion by signing out of the dedicated Access application and signing back in. Reusing a still-cached assertion cannot recreate its old session.

**429:** too many distinct assertions remain unexpired. The default HA cap includes revoked/used assertion hashes until their original expiry; waiting for expiry releases capacity. Do not delete the revocation store. Inspect whether a client is repeatedly forcing new Access logins.

**200 from `/healthz`, but session creation fails:** liveness proves only that the gateway is serving HTTP. It does not verify the Access key service, HA integration, configured account or durable storage. Use the authenticated demo to test the exchange, without device commands.

**502/503:** check gateway-to-HA connectivity, server certificate trust, key-service availability and HA storage permissions. The service deliberately rejects redirects at both the key-fetch and proxy boundaries. Fix the configured final endpoint rather than weakening verification.

**404 on a REST API, `/auth/*`, or a query-string asset:** expected under v1's default route contract. Use the explicit exchange and HA WebSocket. The optional artwork and HA login routes below require separate configuration. Query-based cache busting is unsupported; use content-hashed asset filenames if needed.

**WebSocket reconnects:** expected at the configured maximum connection age, even if the Access session lasts longer. Obtain/reuse an unexpired short token through the exchange and reconnect. The demo does not perform device operations or open a WebSocket.

## Startup diagnostics

Pass `--tls-cert` and `--tls-key` together. The CLI rejects an unmatched flag
before reading configuration or constructing the gateway. `--version` still
prints the version without requiring configuration or TLS files.

Configuration startup errors include a fixed category, without printing the
configuration path, JSON field names or values:

- `not_found`: the configuration file could not be found.
- `permission_denied`: the operating system denied access to the file.
- `open_failed`: another file-opening error occurred.
- `invalid_json`: the first JSON value could not be decoded into the gateway
  configuration, including unknown fields or incorrect value types.
- `trailing_data`: additional data follows the configuration value. Keep one
  JSON object; trailing whitespace is allowed.

Check file availability and permissions using the gateway's service account.
Inspect malformed configuration locally; do not paste private paths, fields or
values into logs or issue reports. These categories do not replace the existing
semantic configuration checks performed before a listener starts.

## Updates and removal

Follow the [staged upgrade and rollback procedure](installation.md#upgrade-and-rollback). HA configuration reload alone is not an integration upgrade; restart HA after replacing the files. The expected reauthentication after that restart is part of the replay-prevention policy.

Install matching component versions and retain HA's revocation storage across updates. Keep issuer/origin/client ID stable. Before changing the origin or removing the integration, revoke its managed `HA Access Session` refresh tokens in the HA profile or an administrator-controlled HA maintenance procedure. Stop the gateway before changing trust settings. Removing a component or changing the client ID cannot retroactively discover tokens stored under a former client ID.

Do not configure request/response logging to capture assertion headers, HA token bodies or WebSocket authentication messages. Gateway error logs intentionally contain no request URLs, claims, tokens or backend bodies. Synthetic examples are suitable for bug reports after confirming they contain no real configuration.

## Optional media-player artwork

`enable_media_artwork` defaults false in the gateway JSON. Embedded Go consumers may set `Config.EnableMediaArtwork: true`. The CLI reads trusted JSON configuration; it has no environment-variable configuration layer. A consuming application may explicitly map its own administrator setting to this field.

When enabled, the gateway accepts only `GET /api/media_player_proxy/media_player.<object_id>`, where the object ID has 1–137 lowercase ASCII letters, digits or underscores. Encoded path aliases, trailing slashes, other entity domains, query strings (including a bare `?`), request bodies and other methods are rejected. The endpoint always belongs to the configured HA upstream; the caller cannot supply a remote image URL.

Send exactly one `Authorization: Bearer <access_token>` header. The token must use bearer-token characters and is bounded to 8,192 characters, including at most two trailing padding characters. The gateway does not replace HA's token validation. The existing signed Access assertion, identity mapping and revocation checks apply as well. No token belongs in the image URL. Use authenticated `fetch`, then the frontend's bounded image-decoding pipeline, rather than an unauthenticated `<img src>` request.

A supplied `Origin` must match the configured public origin exactly. If it is absent, the request must have `Sec-Fetch-Site: same-origin`, as ordinary same-origin browser fetches do. If Fetch Metadata is supplied, only one `same-origin` value is accepted, even when `Origin` is present. A legacy client without Fetch Metadata must supply the exact Origin; JavaScript should not attempt to set browser-controlled headers. Cross-site and same-site requests from another origin are rejected.

Artwork forwards only the existing `Authorization`, `Content-Type` and `Accept` header allowlist and the gateway's configured Origin. Access assertions, cookies, forwarded identities and range headers are not passed to the artwork endpoint. Responses retain `no-store` and the common cookie/CORS stripping. Every upstream 3xx is rejected with 502, including same-origin OAuth callbacks when `enable_ha_login` is enabled. Requests expire after at most 10 seconds, or sooner at assertion expiry, the configured connection deadline or same-process session revocation. Frontends remain responsible for image byte, decoded-pixel and MIME limits; this route streams HA's response and is not an image sanitizer.

## Optional HA login compatibility

`enable_ha_login` defaults false. Existing private dashboards may set it true to retain an explicit normal HA OAuth login fallback. It permits GET `/auth/authorize` with `response_type=code`, client ID and redirect URI equal to the configured origin plus `/`, and a nonempty bounded state. It also permits GET `/auth/providers`; POST `/auth/token`, `/auth/revoke`, `/auth/login_flow`; GET/POST `/auth/login_flow/<32-hex-flow-id>`; and read-only `/frontend_latest/`, `/frontend_es5/`, `/static/`, `/translations/`, `/manifest.json`, `/favicon.ico`. It does not allow arbitrary `/auth/*` paths. OAuth request bodies are capped at 64 KiB. Every route still requires a verified Access assertion; POSTs require the exact Origin. Assertions and proxy identity headers are never forwarded to these login routes.

The root static page may then receive only `code` and `state` query parameters. Upstream HTTP redirects are accepted only to that exact HTTPS origin/root with those two parameters; other redirects remain blocked. Normal HA OAuth issues its own refresh credentials and chooses an account through HA authentication, distinct from the v1 mapped session exchange. Any browser storage for this legacy fallback is the consuming frontend's responsibility. The explicit v1 session exchange continues to return no refresh credential.

`content_security_policy` can override the default static-page CSP for a trusted existing frontend. New dashboards should keep the restrictive default. Only an administrator may set this; permissive inline/blob/frame policies enlarge the frontend trust surface. Embedded Go consumers can supply `Config.StaticFS` instead of `static_dir`; the same static file checks apply.
