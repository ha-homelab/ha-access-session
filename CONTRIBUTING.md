# Contributing

Use English in public issues and pull requests. Include the affected commit/version, synthetic configuration, expected behavior and reproducible steps. Never publish assertions, HA tokens, private identities or home configuration. Use SECURITY.md for confidential findings.

All contributors, including the primary maintainer, must add automated tests for major new functionality and regression tests for fixes. Changes to authentication, revocation, token lifetime, key handling or proxy routes need relevant negative cases and review of docs/security.md. Preserve the fixed-origin and explicit-account boundaries.

Install the pinned development environment as described in README.md. Run `scripts/check.sh`, the real Home Assistant lifecycle canary, and `scripts/build.sh`; inspect the current PR's Python/Go, browser, CodeQL and dependency results. Follow existing Ruff formatting and Go gofmt/vet conventions. Document changed behavior and assigned security advisory identifiers in CHANGELOG.md. Preserve original and third-party license notices.

Follow CODE_OF_CONDUCT.md and GOVERNANCE.md. Suggestions and defects receive a constructive response; explain compatibility and security tradeoffs in review. See RELEASING.md for the separate release acceptance process.
