# Security

Read the [threat model](docs/security.md) and [transport profile](docs/tls-policy.md) before deployment. This package grants one explicitly mapped Home Assistant administrator's privileges.

Report confidential findings through [GitHub private vulnerability reporting](https://github.com/ha-homelab/ha-access-session/security/advisories/new) or **alvit.work@gmail.com**. Private GitHub reporting was enabled and verified on 2026-10-16. Provide affected versions/commits, impact and a synthetic reproducer; never publish real assertions, tokens, identities or home configuration.

Current main and the latest stable release receive security fixes. We aim to acknowledge within seven days, prioritize critical vulnerabilities immediately, and resolve publicly known medium-or-higher vulnerabilities within 60 days of public knowledge. Coordinate disclosure with the reporter and credit them unless they request anonymity. Security notes include assigned identifiers and affected versions. These are response policies, not invented historical response measurements.

No vulnerability reports were received outside GitHub during the preceding twelve months, as confirmed by the maintainer. Deployers must also maintain Home Assistant, their TLS terminators and Cloudflare policy; passing isolated tests does not establish real cloud acceptance or secure configuration of those components.
