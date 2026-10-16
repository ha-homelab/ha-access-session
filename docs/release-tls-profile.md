# Verified release-client transport profile

The signed-release path uses two separately qualified clients. Use both profiles:

- [Patched Cosign signer/verifier](release-signer.md): Cosign 3.1.3 source built
  with Go 1.27.2 and the checked-in patched module graph.
- [Pinned GitHub CLI](release-github-cli.md): official GitHub CLI 2.102.0 with
  Go 1.27.1, installed only after archive and binary hash verification.

The generated release workflow installs these exact clients before the operations
that need them and sets `GODEBUG=fips140=on`. Local operators must follow both
installation guides, put the reviewed executables first in PATH, and keep that
setting for the Python release helper and all inherited subprocesses. The helper
has no option that bypasses release checks or publication approval.

Both profiles preserve certificate and hostname verification and require TLS 1.2
or TLS 1.3 with ephemeral key exchange. Their Go runtime filter checks the entire
verified certificate chain, including RSA keys of at least 2048 bits. The linked
qualification records describe positive and weak-chain negative experiments on
the actual clients, signature verification, and modified-file rejection. They do
not claim this project has published a new release or completed device acceptance.

The former upstream Cosign 3.1.3 executable with Go 1.26.4 is not the supported
release-client profile: its dated dependency findings motivated the patched build.
Follow the dated, command-specific advisory assessments in both guides; neither
claims every feature of either external tool is free of vulnerabilities. Other
versions, custom endpoints, alternative signing providers and custom trust stores
require separate qualification. Git, package managers, and the application itself
retain their own transport and dependency requirements. This runtime setting is
not a FIPS certificate.
