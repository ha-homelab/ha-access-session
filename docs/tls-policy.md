# HTTPS and signing-key policy

The maintained project is the complete Python Home Assistant integration and Go gateway. Neither an offline test component nor a browser mock replaces the complete deployment. This profile requires current builds with Go 1.27.2 and a supported Home Assistant Python runtime exposing the verified certificate chain.

## Owned connections

The Python issuer fetch uses an owned SSL context on the existing HA aiohttp session. It preserves certificate and hostname verification, requires TLS 1.2 or newer and checks every verified-chain certificate before application IO. RSA/DSA require at least 2048 bits (DSA subgroup 224), elliptic keys at least 224 bits; standard Ed25519/Ed448 are supported. Exact RSA modulus length matters because OpenSSL security level 2 can accept a 2047-bit key. Unsupported chain APIs fail closed. The context does not alter HA's global client policy.

The Go issuer and HA upstream transports require TLS 1.2 or newer with modern authenticated TLS 1.2 suites. Normal chain/hostname verification runs before exact RSA/elliptic key checks; at least one complete verified chain must meet the floor. These transports do not inherit ambient proxies. Go issuer keys are filtered before the go-oidc cache; both components require RS256, signature use and an RSA modulus of at least 2048 bits. Rotation, issuer/audience/identity/lifetime checks and fixed destinations still apply.

## HTTPS gateway deployment

Configure the existing Cloudflare Access edge to use a verified HTTPS gateway origin. Start the gateway with a certificate valid for that origin and its matching private key:

```sh
./ha-access-gateway -config /PRIVATE/gateway.json -listen 127.0.0.1:8443 \
  -tls-cert /PRIVATE/gateway-chain.pem -tls-key /PRIVATE/gateway-key.pem
```

The listener checks every supplied certificate's key floor before starting. It requires TLS 1.2 or newer; the edge must independently verify its chain and hostname. Use a non-loopback listener only when required by your topology and restrict it to the edge. Preserve the documented public Host, Origin and signed assertion forwarding.

Set the gateway's upstream to the actual HTTPS Home Assistant origin and leave `allow_insecure_upstream` false. Configure HA's supported HTTPS certificate/key options or an independently maintained validating TLS terminator, using keys at or above the same minimum. Do not disable origin verification. The public browser origin and issuer must remain HTTPS. Keep all private keys and configuration outside the repository, readable only by their service accounts.

The existing HTTP listener and explicit insecure upstream option remain compatibility modes and are excluded from this HTTPS profile. They carry bearer credentials in plaintext across the selected link. The project does not automatically configure or certify Cloudflare policies, edge TLS, Home Assistant's server, DNS or network isolation.

## Evidence and remaining qualification

Local regression tests use real signatures and TLS 1.2/1.3 sessions: 2048-bit RSA works; 2047-bit signing keys and weak root/intermediate/leaf certificate chains fail before an authenticated HTTP request. Python tests use the actual aiohttp SSLObject path, including ECDSA positive controls. The gateway's HTTPS certificate preflight rejects weak supplied chains. These tests use synthetic state and no cloud account or live home installation.

Go 1.27.2 source govulncheck reports no vulnerabilities in the current gateway dependency graph on 2026-10-16. The release pipeline uses the separately qualified [signer and GitHub CLI profiles](release-tls-profile.md); their exact versions and command-specific advisory assessments remain distinct from the application runtime. Home Assistant, browsers and external TLS terminators require their own current dependency review. The complete external deployment acceptance checklist in installation.md remains necessary; unit tests do not claim that cloud SSO or production deployment was tested.
