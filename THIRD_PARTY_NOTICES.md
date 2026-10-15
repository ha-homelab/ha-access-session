# Third-party notices

The HA Access Session source is MIT licensed. Its authentication boundary was extracted and generalized from contributor-owned private code with permission. No third-party dashboard assets, home models, photographs or icon libraries are included. The synthetic HTML/CSS/JavaScript demo is original project code.

## Gateway binary dependencies

- Go standard library/runtime: BSD-style license, Google and Go contributors. See `licenses/Go-LICENSE`.
- `github.com/coreos/go-oidc/v3` v3.18.0: Apache-2.0. Full license and upstream attribution notice are included under `licenses/go-oidc-*`.
- `github.com/go-jose/go-jose/v4` v4.1.4: Apache-2.0. See `licenses/go-jose-LICENSE`.
- `golang.org/x/oauth2` v0.36.0: BSD-3-Clause. See `licenses/oauth2-LICENSE`.

Exact module checksums are recorded in `go.sum`. Release archives include these notices and license texts. A rebuilt binary may use a newer Go runtime; retain that runtime's license.

## HA runtime and test dependencies

The integration runs inside Home Assistant (Apache-2.0) and uses its installed auth/http/storage helpers, aiohttp (Apache-2.0), PyJWT (MIT), cryptography (Apache-2.0 OR BSD-3-Clause), and voluptuous (BSD-3-Clause). Those packages are not vendored in the integration ZIP. The supported public beta scope is the isolated test contract, not a claim of compatibility with every HA version.

Development dependencies and transitive versions are recorded in `requirements-dev.lock`. Ruff is MIT licensed; Python is PSF licensed. Installed distributions retain their own license files. `licenses/PyJWT-LICENSE`, `licenses/aiohttp-LICENSE`, `licenses/voluptuous-LICENSE`, and `licenses/cryptography-*` are included for reference. Dependency licenses remain their respective authors' licenses, not the project's MIT grant.

## Shared release tooling

Generated release and workflow-contract helpers are from [venus-os-ci-toolkit](https://github.com/victron-venus/venus-os-ci-toolkit), pinned by `.release-policy.json`. The following license applies to those files.

MIT License

Copyright (c) 2026 victron-venus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
