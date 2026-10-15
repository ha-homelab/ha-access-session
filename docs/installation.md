# Install, qualify and upgrade

HA Access Session has two components: a YAML-configured Home Assistant custom integration and a separate Go gateway. It is not an HA add-on, a HACS UI installation, or a replacement HA login provider. The same release supplies both components. Start with the [tested compatibility scope](compatibility.md) and use a disposable HA instance for your first deployment.

## Prepare the boundary

Choose a dedicated public HTTPS origin, such as `https://dashboard.example.invalid`, and a dedicated Cloudflare Access application for it. Both components need the exact issuer, audience, origin and case-sensitive mapped email. Origins have no trailing slash. Keep the Access assertion lifetime at or below `max_assertion_lifetime_seconds` (default 86,400 seconds).

Choose one existing HA administrator explicitly. The configured `user_id` must be that account's 32-character lowercase hexadecimal ID; the example's zero-filled ID cannot work. Use your authenticated HA user-management tooling to obtain the ID and verify the account, without publishing the result. Do not select the first administrator in storage or copy an example identity. The account must be active, not local-only and not system-generated. This integration grants that administrator's full authority.

Keep `allow_trusted_network` false unless you intentionally want a signed anonymous network assertion to grant the same administrator authority. If enabling it, read the [separate trust model](security.md#explicit-trusted-network-admission) first and configure both components consistently.

Plan network reachability before installation:

- The browser reaches the dedicated HTTPS Access-protected origin.
- The edge reaches the gateway and preserves the public `Host`, browser `Origin` and signed `Cf-Access-Jwt-Assertion` header.
- The gateway reaches the configured HA origin. HTTPS certificates must validate; there is no skip-verification option.
- HA and the gateway can reach the fixed HTTPS issuer key endpoint. Synchronize their clocks.

Use an isolated network and explicit `allow_insecure_upstream: true` only if the gateway-to-HA link must use HTTP. That link carries assertions and short-lived tokens in plaintext. Restrict direct access to both HA and the gateway; direct HA connections are outside the gateway's connection limit.

## Download and stage one release

Select a specific published tag. Complete [signed-release verification](release-signatures.md) on its assets before extraction. Use Linux `amd64` for x86-64 or `arm64` for AArch64; the archives do not contain macOS or Windows executables. An RC may embed the final base version because stable promotion reuses its bytes. Use the signed release manifest and tag to identify the channel, not only `-version` output.

Extract the verified integration ZIP into an empty staging directory. It contains documentation and licenses alongside `custom_components/ha_access_session`; do not unzip the entire archive over an existing HA configuration directory. Copy only the `ha_access_session` directory into HA's `custom_components` directory. Preserve the accompanying license material with your downloaded release.

The final layout is:

```text
<HA configuration directory>/
  configuration.yaml
  custom_components/
    ha_access_session/
      __init__.py
      access.py
      manifest.json
```

For HA Container, this is the host directory mounted at `/config` in the container. For HA OS, use your existing supported configuration-file access method to copy the directory. Do not install files into HA's Python `site-packages` or modify HA-managed Python dependencies.

Back up your configuration, then merge the block from [configuration.yaml](../examples/configuration.yaml) into the existing file. Do not replace the whole file or create a duplicate top-level `ha_access_session:` key. Replace all example values, check configuration using HA's normal configuration check, and restart HA. There is no UI config flow or YAML reload handler for this integration.

Extract the matching gateway archive into its own directory. Copy [gateway.json](../examples/gateway.json) to a private configuration location and replace its examples. Unknown JSON fields are rejected. Keep `session_path` unset for the standalone integration, and leave `enable_ha_login` false for the v1 exchange. Run the executable as an unprivileged account with read access to this configuration:

```sh
./ha-access-gateway -version
./ha-access-gateway -config /path/to/gateway.json -listen 127.0.0.1:8080
```

A loopback listener is reachable only from the same host/network namespace. If the edge is in another container or host, select an explicitly reachable listener and firewall it to that edge. Configure your existing service supervisor to restart the gateway after failure and load the same configuration on boot. No HA token, cookie or Access assertion belongs in the service command or environment.

## Acceptance without device commands

1. Check HA logs for successful setup and any configuration/storage errors. A custom-integration warning does not imply failure or HA endorsement.
2. Request gateway `/healthz` locally. A 200 is liveness only; it does not contact HA or the issuer.
3. Visit the public origin through Access. An unauthenticated direct request must not load protected assets. Confirm that an unauthorized Access identity cannot load the dashboard.
4. Use the synthetic demo's **Create real session**. It tests issuance but makes no device calls. Do not copy the response token into a log or issue.
5. Use **Revoke session**, then try creation again with the same assertion. It must fail. Sign out of the dedicated Access application and sign back in for a fresh assertion.
6. Restart the disposable HA instance. The previously used assertion must again fail, even after the gateway restarts. A fresh Access login should work.
7. For your own frontend, verify that its WebSocket reconnects at the configured connection limit, holds tokens in memory, and handles failed exchange/revocation visibly.

Cloud identity, TLS, reverse proxy and browser behavior depend on your deployment. These steps are operator qualification, not claims that the project's offline canary exercises those services. Retain only redacted outcomes and versions as evidence.

## Upgrade and rollback

Read the release notes and [compatibility scope](compatibility.md), download a matching pair of assets and verify their signatures. Retain the previous verified pair. Before changing files, stop the gateway and take your normal HA backup, including configuration and auth/revocation storage.

Stage the new files outside the live configuration. Replace the entire `custom_components/ha_access_session` directory so files removed in a release do not survive the upgrade. Keep the previous directory in your backup location, outside `custom_components`. Replace the gateway executable and any versioned frontend assets from the same release. Retain your reviewed private settings; do not overwrite them with examples.

Preserve `.storage/ha_access_session.used_assertions` and HA's auth store. Never edit or delete those stores to make an old assertion work. Restart HA first, inspect its setup result, then start the matching gateway. Restart intentionally revokes the previous managed refresh tokens; obtain a fresh Access assertion and repeat acceptance.

For a code rollback, stop the gateway and restore the previous matching component files and compatible settings while retaining the latest revocation/auth state. Restart HA and the gateway, then sign in again. Restoring an old whole-system backup can restore credentials and discard later revocations; treat that as security recovery and revoke affected credentials before reopening access.

Before changing origin/client ID or removing the integration, stop the gateway and revoke all managed `HA Access Session` refresh tokens through HA's authenticated profile/administration controls. A new client ID cannot discover credentials issued under the old one. Remove the integration configuration and directory, restart HA, then remove the gateway service and its public route. See [operations](operations.md) for error diagnosis.
