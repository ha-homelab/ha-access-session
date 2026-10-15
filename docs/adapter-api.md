# Thin compatibility adapters

The standalone HA integration provides the public Python implementation in `custom_components.ha_access_session.access`. Install that integration package or vendor its **unmodified versioned directory** and MIT/license notices; do not copy and diverge the verifier logic. The only versioned protocol is contract v1. Pin the Python implementation and Go gateway to the same reviewed release; prerelease implementation APIs may change.

```python
from custom_components.ha_access_session.access import AccessConfig, AccessSessions

settings = AccessConfig(
    issuer="https://access.example.invalid",
    origin="https://dashboard.example.invalid",
    audience="dedicated-application-audience",
    email="owner@example.invalid",
    user_id="00000000000000000000000000000000",
)
view = AccessSessions(
    hass,
    settings,
    persist=store.async_save,             # async callable: dict[sha256, Unix expiry]
    tombstones=await store.async_load() or {},
    session_path="/api/custom_dashboard/access_session",
    client_id=settings.origin + "/custom-dashboard-session",
    view_name="api:custom_dashboard:access_session",
)
hass.http.register_view(view)
```

This snippet illustrates construction, not the complete lifecycle. A private adapter must validate loaded tombstone records, retain only unexpired records, remove existing HA refresh tokens with its **exact stable client ID** before registering after a restart, and supply a durable async persistence callback that raises on failure. The standalone integration's `__init__.py` is the reference setup implementation. Do not pass an in-memory no-op callback outside tests. The view writes a used-assertion tombstone before any credential issuance.

The configurable route must be a canonical `/api/` path. The client ID must belong to the configured public origin. Nothing about the source project's users, domains, or credentials belongs in this shared module. Keep those in private configuration only. `AccessConfig` rejects unknown fields, invalid strings and invalid bounds when constructed from a mapping.

The Go module exports:

```go
handler, err := gateway.New(ctx, gateway.Config{
    Issuer: "https://access.example.invalid",
    Origin: "https://dashboard.example.invalid",
    Audience: "dedicated-application-audience",
    Email: "owner@example.invalid",
    Upstream: "https://ha.example.invalid",
    SessionPath: "/api/custom_dashboard/access_session",
    StaticDir: "/srv/public-dashboard",
})
```

Import `github.com/ha-homelab/ha-access-session/gateway` at the exact release tag. `Gateway` implements `http.Handler`. `New` validates configuration and loads static files before returning; it does not contact the issuer or HA until an actual signed request. Use an HTTP server with header timeouts and bounded header size, as in `cmd/ha-access-gateway/main.go`.

The public browser routes remain `/session/ha`, `/session`, and `/api/websocket`, regardless of the private HA adapter route. Do not widen proxy routing to preserve unrelated private frontend behavior; migrate that frontend explicitly to the v1 contract. Keep a dependency pin and a synthetic boundary test in the consuming project.

For an existing embedded frontend, set `StaticFS` to a rooted `fs.FS` (for example an `embed.FS` subdirectory). Do not also set `StaticDir`. `EnableHALogin: true` opts into the bounded HA OAuth compatibility routes documented in operations. `ContentSecurityPolicy` is an administrator-controlled override for trusted legacy frontends that need frames or inline scripts; it is unnecessary for the public demo. Neither option changes the independently verified v1 exchange.
