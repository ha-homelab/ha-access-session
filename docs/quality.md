# Quality evidence and current limits

The maintained project includes the Python Home Assistant integration, Go gateway,
embedded browser demo, packaging and release helpers. Checking a mock or an offline
component alone does not qualify the complete deployment.

## Repeatable checks

Prepare the development environment from the README, then run `scripts/check.sh`.
This runs Ruff lint/format checks, Python regressions, version consistency, Go
formatting, `go vet` and the Go race suite. Set `HA_PYTHON` to the separate, pinned
Home Assistant environment to include the real lifecycle canary. The required
quality gate additionally runs browser acceptance, workflow/release contracts,
CodeQL and dependency/security checks. `scripts/build.sh` builds both Linux gateway
architectures and packages the matching integration; CI tests the extracted ZIP.

On 2026-10-16 the source checks passed with Python 3.14.7, Home Assistant 2026.10.0
and Go 1.27.2:

- Nineteen Python tests passed, including fourteen real aiohttp TLS cases across
  TLS 1.2 and TLS 1.3. Strong RSA and EC controls succeed; weak leaf, intermediate
  and root keys fail before an authenticated HTTP request.
- The Go race suite passed. Real TLS and JWKS cases calibrate ordinary 2047-bit
  acceptance against the new exact 2048-bit floor. HTTPS listener preflight checks
  reject weak supplied chains before opening a listener.
- Four isolated real-HA lifecycle tests passed for configuration, authentication,
  persistent state, logout, restart and scheduled expiry. They use temporary data
  and disable networking; they do not operate a home installation.
- Source-mode `govulncheck` using the actual Go 1.27.2 toolchain reported no known
  vulnerability in the current gateway graph.
- `pip-audit` 2.10.1 checked all 15 installed development distributions and all 103
  distributions in the separate HA environment without skips or known findings.
  Audit the installed environment, not just the four top-level requirements:

  ```sh
  uvx pip-audit==2.10.1 --strict --path .venv/lib/python3.14/site-packages
  uvx pip-audit==2.10.1 --strict --path .ha-test/lib/python3.14/site-packages
  ```

Use the actual interpreter's site-packages path on other systems. These dated
database checks do not promise absence of unknown vulnerabilities or qualify
different package versions. HA retains its own dependency constraints; do not
overwrite them with the development lock.

The HA canary emits its normal custom-integration support notice. Its debug loop
can also report a slow task while generating synthetic test keys. These are
documented test-environment diagnostics, not ignored authentication failures. The
dependency audit discarded two unreadable cached HTTP entries and successfully
fetched current results; no package was excluded.

## Remaining work

This evidence does not establish complete line/branch coverage, ongoing fuzzing,
an independent security audit, reproducible gateway binaries, universal browser
accessibility or compatibility beyond the named HA version. Release builds
currently strip Go debug information. The owner has no designated backup or
tested one-week access-recovery arrangement.

The [transport policy](tls-policy.md) documents owned HTTPS enforcement and an
explicit HTTP compatibility mode. External Cloudflare, browser, HA HTTPS-server
and TLS-terminator configuration still need the installation acceptance checks.
The pinned generated release-signing and GitHub clients also need their current
complete dependency/TLS qualification; the runtime audits above do not cover
those binaries. Until these boundaries are qualified, do not claim complete
deployment or release-tool cryptographic readiness.
