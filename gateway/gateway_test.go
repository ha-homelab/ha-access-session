package gateway

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

func config() Config {
	return Config{Issuer: "https://access.example.invalid", Origin: "https://dashboard.example.invalid",
		Audience: "test-audience", Email: "owner@example.invalid", Upstream: "https://ha.example.invalid"}
}
func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func claimsMap() map[string]any {
	return map[string]any{"iss": config().Issuer, "aud": []string{config().Audience},
		"sub": "owner-subject", "email": config().Email, "type": "app", "iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}
}
func signed(t *testing.T, k *rsa.PrivateKey, c map[string]any) string {
	t.Helper()
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key"}`)) + "." + base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(message))
	sig, e := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func fixture(t *testing.T, upstream http.Handler) (*Gateway, *rsa.PrivateKey) {
	t.Helper()
	k := key(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(jwks.Close)
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	c := config()
	c.Upstream = backend.URL
	c.AllowInsecureUpstream = true
	verifier := oidc.NewVerifier(c.Issuer, oidc.NewRemoteKeySet(context.Background(), jwks.URL),
		&oidc.Config{ClientID: c.Audience, SupportedSigningAlgs: []string{oidc.RS256}})
	g, e := newWithVerifier(c, verifier)
	if e != nil {
		t.Fatal(e)
	}
	return g, k
}
func invoke(g *Gateway, method, path, token string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, config().Origin+path, nil)
	if token != "" {
		r.Header.Set(AssertionHeader, token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}
func TestInvalidIdentityNeverReachesBackend(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "https://evil.example.invalid" }},
		{"audience", func(c map[string]any) { c["aud"] = "wrong-app" }},
		{"expiry", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Second).Unix() }},
		{"missing expiry", func(c map[string]any) { delete(c, "exp") }},
		{"long expiry", func(c map[string]any) { c["exp"] = time.Now().Add(25 * time.Hour).Unix() }},
		{"future issuance", func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"future nbf", func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{"null nbf", func(c map[string]any) { c["nbf"] = nil }},
		{"email", func(c map[string]any) { c["email"] = "other@example.invalid" }},
		{"missing email", func(c map[string]any) { delete(c, "email") }},
		{"subject", func(c map[string]any) { delete(c, "sub") }},
		{"anonymous", func(c map[string]any) { c["sub"] = ""; delete(c, "email") }},
		{"service identity", func(c map[string]any) { c["common_name"] = "service" }},
		{"null service identity", func(c map[string]any) { c["common_name"] = nil }},
		{"type", func(c map[string]any) { c["type"] = "org" }},
		{"numeric subject", func(c map[string]any) { c["sub"] = 5 }},
		{"boolean issuance", func(c map[string]any) { c["iat"] = true }},
		{"fractional expiry", func(c map[string]any) { c["exp"] = float64(time.Now().Add(time.Hour).Unix()) + 0.5 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := claimsMap()
			tc.edit(c)
			if w := invoke(g, "POST", "/session/ha", signed(t, k, c), map[string]string{"Origin": config().Origin}); w.Code < 400 {
				t.Fatalf("accepted: %d", w.Code)
			}
		})
	}
	for _, raw := range []string{"", "forged", signed(t, key(t), claimsMap()), "eyJhbGciOiJub25lIn0.e30.", strings.Repeat("a", 16385)} {
		if invoke(g, "GET", "/session", raw, map[string]string{"Authorization": "Bearer fake", "Cookie": "CF_Authorization=fake", "X-Forwarded-User": config().Email}).Code != 401 {
			t.Fatal("spoof accepted")
		}
	}
	r := httptest.NewRequest("GET", config().Origin+"/session", nil)
	r.Header.Add(AssertionHeader, signed(t, k, claimsMap()))
	r.Header.Add(AssertionHeader, signed(t, k, claimsMap()))
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("duplicate assertions accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("invalid identity reached backend")
	}
}
func TestExchangeBoundaryAndRevocation(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "POST" || r.URL.Path != SessionPath || r.Host != "dashboard.example.invalid" || r.Header.Get(AssertionHeader) == "" || r.Header.Get("Origin") != config().Origin {
			t.Error("incorrect exchange")
		}
		for _, h := range []string{"Authorization", "Cookie", "Cf-Access-Authenticated-User-Email", "X-Forwarded-User", "Forwarded", "Impersonate-User"} {
			if r.Header.Get(h) != "" {
				t.Errorf("leaked %s", h)
			}
		}
		w.Header().Set("Set-Cookie", "fake=value")
		if r.URL.RawQuery == "revoke=1" {
			w.WriteHeader(204)
		} else {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"contract_version":1,"access_token":"synthetic","expires_in":300,"session_expires_at":1}`))
		}
	}))
	raw := signed(t, k, claimsMap())
	headers := map[string]string{"Origin": config().Origin, "Cookie": "fake", "Authorization": "Bearer fake", "X-Forwarded-User": "fake", "Cf-Access-Authenticated-User-Email": "fake"}
	w := invoke(g, "POST", "/session/ha", raw, headers)
	if w.Code != 200 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("exchange failed")
	}
	if invoke(g, "POST", "/session/ha?revoke=1", raw, headers).Code != 204 {
		t.Fatal("revoke failed")
	}
	if invoke(g, "POST", "/session/ha", raw, headers).Code != 401 {
		t.Fatal("revoked assertion reused")
	}
	if hits.Load() != 2 {
		t.Fatal("unexpected backend calls")
	}
}
func TestRouteMethodOriginAndQueryAllowlists(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	raw := signed(t, k, claimsMap())
	for _, tc := range []struct{ method, path, origin string }{
		{"GET", "/session/ha", config().Origin}, {"POST", "/session/ha", ""}, {"POST", "/session/ha", "https://evil.example.invalid"},
		{"POST", "/session/ha?user_id=attacker", config().Origin}, {"POST", "/session/ha?revoke=1&revoke=1", config().Origin},
		{"POST", SessionPath, config().Origin}, {"POST", "/api/services/light/turn_on", config().Origin},
		{"GET", "/api/states", config().Origin}, {"POST", "/auth/token", config().Origin}, {"GET", "/auth/providers", config().Origin},
		{"GET", "/api/websocket", config().Origin}, {"GET", "/../index.html", config().Origin}, {"GET", "/%61pp.js", config().Origin},
		{"GET", "//evil.example.invalid/", config().Origin},
	} {
		if invoke(g, tc.method, tc.path, raw, map[string]string{"Origin": tc.origin}).Code < 400 {
			t.Errorf("accepted %s %s", tc.method, tc.path)
		}
	}
	for _, h := range []map[string]string{{"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}, {"Origin": "https://evil.example.invalid"}} {
		if invoke(g, "GET", "/", raw, h).Code != 403 {
			t.Fatal("CSRF accepted")
		}
	}
	r := httptest.NewRequest("GET", "https://wrong.example.invalid/", nil)
	r.Header.Set(AssertionHeader, raw)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("host accepted")
	}
	body := httptest.NewRequest("POST", config().Origin+"/session/ha", strings.NewReader(`{"user_id":"attacker"}`))
	body.Header.Set("Origin", config().Origin)
	body.Header.Set(AssertionHeader, raw)
	w = httptest.NewRecorder()
	g.ServeHTTP(w, body)
	if w.Code < 400 {
		t.Fatal("body accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("unapproved route reached backend")
	}
}
func TestAssetsAndHealth(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	raw := signed(t, k, claimsMap())
	for _, p := range []string{"/", "/app.js", "/style.css", "/session"} {
		if invoke(g, "GET", p, "", nil).Code != 401 {
			t.Fatal("unprotected asset")
		}
		w := invoke(g, "GET", p, raw, nil)
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("missing %s", p)
		}
	}
	if invoke(g, "GET", "/healthz?target=evil", "", map[string]string{"Authorization": "Bearer fake"}).Code != 200 {
		t.Fatal("health failed")
	}
	if hits.Load() != 0 {
		t.Fatal("health/static forwarded request")
	}
}
func TestTrustedNetworkRequiresOptInAndExactClaims(t *testing.T) {
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c := claimsMap()
	c["sub"] = ""
	delete(c, "email")
	raw := signed(t, k, c)
	if invoke(g, "GET", "/session", raw, nil).Code < 400 {
		t.Fatal("network enabled by default")
	}
	g.config.AllowTrustedNetwork = true
	if invoke(g, "GET", "/session", raw, nil).Code != 200 {
		t.Fatal("opt-in failed")
	}
	for _, change := range []map[string]any{{"email": nil}, {"common_name": nil}, {"common_name": "service"}, {"sub": nil}, {"sub": "service"}, {"email": "other@example.invalid"}} {
		changed := map[string]any{}
		for k, v := range c {
			changed[k] = v
		}
		for k, v := range change {
			changed[k] = v
		}
		if invoke(g, "GET", "/session", signed(t, k, changed), nil).Code < 400 {
			t.Fatal("invalid network admitted")
		}
	}
}
func TestConfigurationRejectsUnsafeInputs(t *testing.T) {
	for _, edit := range []func(*Config){
		func(c *Config) { c.Issuer = "http://access.example.invalid" }, func(c *Config) { c.Origin += "/" },
		func(c *Config) { c.Origin = "https://user@dashboard.example.invalid" }, func(c *Config) { c.Upstream = "http://ha.example.invalid" },
		func(c *Config) { c.Upstream += "/api" }, func(c *Config) { c.Audience = "" }, func(c *Config) { c.Email = "invalid" },
		func(c *Config) { c.MaxConnectionSeconds = 301 }, func(c *Config) { c.MaxAssertionLifetimeSeconds = 86401 },
		func(c *Config) { c.SessionPath = "https://evil.example.invalid" }, func(c *Config) { c.SessionPath = "/api/../config" },
	} {
		c := config()
		edit(&c)
		if c.normalize() == nil {
			t.Fatalf("unsafe config accepted: %#v", c)
		}
	}
}
func TestStaticDirectoryDoesNotExposeHiddenFilesOrSymlinks(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "index.html"), []byte("demo"), 0600); e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(filepath.Join(dir, ".hidden.js"), []byte("private"), 0600)
	files, e := loadFiles(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := files["/.hidden.js"]; ok {
		t.Fatal("hidden asset exposed")
	}
	if e = os.Symlink(filepath.Join(dir, "index.html"), filepath.Join(dir, "alias.html")); e != nil {
		t.Fatal(e)
	}
	if _, e = loadFiles(dir); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestUpstreamRedirectIsBlocked(t *testing.T) {
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://evil.example.invalid", 302) }))
	w := invoke(g, "POST", "/session/ha", signed(t, k, claimsMap()), map[string]string{"Origin": config().Origin})
	if w.Code != 502 || w.Header().Get("Location") != "" {
		t.Fatal("redirect escaped boundary")
	}
}
func TestWebSocketIsClosedAtExpiryAndOnLogout(t *testing.T) {
	for _, mode := range []string{"connection", "assertion", "logout"} {
		t.Run(mode, func(t *testing.T) {
			g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == SessionPath {
					w.WriteHeader(204)
					return
				}
				if r.Header.Get(AssertionHeader) != "" || r.Header.Get("Cookie") != "" {
					t.Error("identity leaked to websocket")
				}
				conn, rw, e := w.(http.Hijacker).Hijack()
				if e != nil {
					t.Error(e)
					return
				}
				defer conn.Close()
				_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				_ = rw.Flush()
				b := make([]byte, 4)
				_, _ = io.ReadFull(rw, b)
				_, _ = conn.Write(b)
				_, _ = io.Copy(io.Discard, rw)
			}))
			g.config.MaxConnectionSeconds = 1
			if mode == "assertion" {
				g.config.MaxConnectionSeconds = 300
			}
			server := httptest.NewServer(g)
			defer server.Close()
			conn, e := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			testClaims := claimsMap()
			if mode == "assertion" {
				testClaims["exp"] = time.Now().Add(2 * time.Second).Unix()
			}
			raw := signed(t, k, testClaims)
			_, _ = fmt.Fprintf(conn, "GET /api/websocket HTTP/1.1\r\nHost: dashboard.example.invalid\r\nOrigin: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n%s: %s\r\n\r\n", config().Origin, AssertionHeader, raw)
			reader := bufio.NewReader(conn)
			response, e := http.ReadResponse(reader, nil)
			if e != nil || response.StatusCode != 101 {
				t.Fatalf("upgrade failed: %v", e)
			}
			_, _ = conn.Write([]byte("ping"))
			b := make([]byte, 4)
			if _, e = io.ReadFull(reader, b); e != nil || string(b) != "ping" {
				t.Fatal("stream failed")
			}
			if mode == "logout" && invoke(g, "POST", "/session/ha?revoke=1", raw, map[string]string{"Origin": config().Origin}).Code != 204 {
				t.Fatal("logout failed")
			}
			if _, e = reader.ReadByte(); e != io.EOF {
				t.Fatalf("stream survived boundary: %v", e)
			}
		})
	}
}

func TestProtectedHeaderPolicy(t *testing.T) {
	for _, raw := range []string{`{"alg":"none","kid":"key"}`, `{"alg":"RS256"}`, `{"alg":"RS256","kid":null}`, `{"alg":"RS256","kid":"key","crit":["unknown"]}`} {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(raw)) + ".e30.fake"
		if validProtectedHeader(encoded) {
			t.Fatal("invalid protected header accepted")
		}
	}
}

func TestSignatureEncodingAliasesCannotBypassRevocation(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	raw := signed(t, k, claimsMap())
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alias := raw[:len(raw)-1] + string(alphabet[strings.IndexByte(alphabet, raw[len(raw)-1])+1])
	headers := map[string]string{"Origin": config().Origin}
	if invoke(g, "POST", "/session/ha?revoke=1", raw, headers).Code != http.StatusNoContent {
		t.Fatal("revocation failed")
	}
	for _, alternative := range []string{raw, raw + "=", raw + "==", alias} {
		if invoke(g, "POST", "/session/ha", alternative, headers).Code != http.StatusUnauthorized {
			t.Fatal("revoked assertion or its encoding alias accepted")
		}
	}
	if hits.Load() != 1 {
		t.Fatal("revoked assertion reached backend")
	}
}

func TestKeyFetchFailureRejectsOwner(t *testing.T) {
	k := key(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer jwks.Close()
	verifier := oidc.NewVerifier(config().Issuer, oidc.NewRemoteKeySet(context.Background(), jwks.URL),
		&oidc.Config{ClientID: config().Audience, SupportedSigningAlgs: []string{oidc.RS256}})
	g, err := newWithVerifier(config(), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if invoke(g, "GET", "/", signed(t, k, claimsMap()), nil).Code != http.StatusUnauthorized {
		t.Fatal("key-service failure did not fail closed")
	}
}

func TestHALoginAuthenticationIsNotReplacedByAccess(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get(AssertionHeader) != "" {
			t.Error("gateway invented HA credentials")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	g.config.EnableHALogin = true
	if invoke(g, "POST", "/auth/token", signed(t, k, claimsMap()), map[string]string{"Origin": config().Origin}).Code != http.StatusUnauthorized {
		t.Fatal("Access identity bypassed HA authentication")
	}
	if hits.Load() != 1 {
		t.Fatal("HA did not make the authentication decision")
	}
}

func TestOptionalHALoginPreservesCredentialsWithoutForwardingAccessIdentity(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get(AssertionHeader) != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-User") != "" {
			t.Error("identity leaked to OAuth")
		}
		if r.URL.Path == "/auth/token" && (r.Header.Get("Authorization") != "Bearer synthetic" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded") {
			t.Error("HA user request was not preserved")
		}
		w.WriteHeader(200)
	}))
	raw := signed(t, k, claimsMap())
	headers := map[string]string{"Origin": config().Origin, "Authorization": "Bearer synthetic", "Content-Type": "application/x-www-form-urlencoded", "Cookie": "fake", "X-Forwarded-User": "fake"}
	if invoke(g, "POST", "/auth/token", raw, headers).Code != 404 {
		t.Fatal("OAuth enabled by default")
	}
	g.config.EnableHALogin = true
	for _, test := range []struct{ method, path string }{
		{"POST", "/auth/token"}, {"GET", "/auth/providers"}, {"POST", "/auth/login_flow"},
		{"POST", "/auth/login_flow/0123456789abcdef0123456789abcdef"},
		{"GET", "/frontend_latest/auth.js"}, {"GET", "/static/fonts/font.woff2"},
		{"GET", "/auth/authorize?response_type=code&client_id=https%3A%2F%2Fdashboard.example.invalid%2F&redirect_uri=https%3A%2F%2Fdashboard.example.invalid%2F&state=nonce"},
	} {
		if w := invoke(g, test.method, test.path, raw, headers); w.Code != 200 {
			t.Errorf("login route rejected %s: %d", test.path, w.Code)
		}
	}
	for _, path := range []string{
		"/auth/authorize?response_type=code&client_id=https%3A%2F%2Fevil.example.invalid%2F&redirect_uri=https%3A%2F%2Fevil.example.invalid%2F&state=nonce",
		"/auth/authorize?response_type=token", "/auth/token?redirect=evil", "/auth/arbitrary", "/api/states",
	} {
		if invoke(g, "GET", path, raw, headers).Code < 400 {
			t.Errorf("unsafe login route accepted: %s", path)
		}
	}
	if invoke(g, "GET", "/?code=synthetic&state=nonce", raw, nil).Code != 200 {
		t.Fatal("same-origin callback not served")
	}
	if hits.Load() != 7 {
		t.Fatalf("unexpected backend calls: %d", hits.Load())
	}
}

func TestAuthenticatedCrossSiteDocumentNavigation(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	raw := signed(t, k, claimsMap())
	headers := map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	if w := invoke(g, "GET", "/", raw, headers); w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("authenticated document navigation failed: %d", w.Code)
	}
	if w := invoke(g, "GET", "/", "", headers); w.Code != http.StatusUnauthorized {
		t.Fatalf("navigation bypassed assertion requirement: %d", w.Code)
	}
	other := claimsMap()
	other["email"] = "other@example.invalid"
	if w := invoke(g, "GET", "/", signed(t, k, other), headers); w.Code != http.StatusForbidden {
		t.Fatalf("navigation bypassed identity mapping: %d", w.Code)
	}
	for _, tc := range []struct{ method, path, mode, destination, origin string }{
		{"POST", "/", "navigate", "document", ""},
		{"GET", "/session", "navigate", "document", ""},
		{"POST", "/session/ha", "navigate", "document", config().Origin},
		{"GET", "/api/websocket", "websocket", "empty", config().Origin},
		{"GET", "/app.js", "navigate", "document", ""},
		{"GET", "/", "cors", "document", ""},
		{"GET", "/", "navigate", "iframe", ""},
		{"GET", "/", "navigate", "document", "https://other.example.invalid"},
	} {
		h := map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": tc.mode, "Sec-Fetch-Dest": tc.destination}
		if tc.origin != "" {
			h["Origin"] = tc.origin
		}
		if w := invoke(g, tc.method, tc.path, raw, h); w.Code != http.StatusForbidden {
			t.Errorf("cross-site request accepted: %s %s %s %s: %d", tc.method, tc.path, tc.mode, tc.destination, w.Code)
		}
	}
	r := httptest.NewRequest("GET", config().Origin+"/", nil)
	r.Header.Set(AssertionHeader, raw)
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	r.Header.Add("Sec-Fetch-Mode", "cors")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("ambiguous navigation metadata accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("navigation forwarded a request to Home Assistant")
	}
}
