package gateway

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

//go:embed web/*
var embedded embed.FS

type claims struct {
	Email      json.RawMessage `json:"email"`
	Subject    *string         `json:"sub"`
	CommonName json.RawMessage `json:"common_name"`
	Type       string          `json:"type"`
	IssuedAt   int64           `json:"iat"`
	NotBefore  json.RawMessage `json:"nbf"`
	Expires    int64           `json:"exp"`
}

type active struct {
	expires time.Time
	cancels map[uint64]context.CancelFunc
}

// Gateway admits only signed identities, static files and explicit HA routes.
type Gateway struct {
	config   Config
	verifier *oidc.IDTokenVerifier
	proxy    *httputil.ReverseProxy
	files    map[string][]byte
	host     string
	mu       sync.Mutex
	revoked  map[string]time.Time
	active   map[string]*active
	next     uint64
}

// New validates trusted configuration. The returned HTTP handler contains no HA credentials.
func New(ctx context.Context, config Config) (*Gateway, error) {
	if err := config.normalize(); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: keySetTransport{secureTransport()},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ctx = oidc.ClientContext(ctx, client)
	keys := oidc.NewRemoteKeySet(ctx, config.Issuer+"/cdn-cgi/access/certs")
	verifier := oidc.NewVerifier(config.Issuer, keys, &oidc.Config{ClientID: config.Audience,
		SupportedSigningAlgs: []string{oidc.RS256}})
	return newWithVerifier(config, verifier)
}

func loadFiles(dir string, provided ...fs.FS) (map[string][]byte, error) {
	var source fs.FS
	if len(provided) > 0 && provided[0] != nil {
		source = provided[0]
	} else if dir == "" {
		source, _ = fs.Sub(embedded, "web")
	} else {
		source = os.DirFS(dir)
	}
	files := make(map[string][]byte)
	err := fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not allowed in static_dir")
		}
		if name != "." && strings.HasPrefix(entry.Name(), ".") {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(path.Ext(name)) {
		case ".html", ".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff2":
		default:
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 4<<20 || len(files) >= 1024 {
			return fmt.Errorf("static file limit exceeded")
		}
		data, err := fs.ReadFile(source, name)
		if err != nil {
			return err
		}
		files["/"+filepath.ToSlash(name)] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data, ok := files["/index.html"]; ok {
		files["/"] = data
	} else {
		return nil, fmt.Errorf("static_dir requires index.html")
	}
	return files, nil
}

func newWithVerifier(c Config, verifier *oidc.IDTokenVerifier) (*Gateway, error) {
	if err := c.normalize(); err != nil {
		return nil, err
	}
	files, err := loadFiles(c.StaticDir, c.StaticFS)
	if err != nil {
		return nil, err
	}
	public, _ := url.Parse(c.Origin)
	upstream, _ := url.Parse(c.Upstream)
	g := &Gateway{config: c, verifier: verifier, files: files, host: public.Host,
		revoked: make(map[string]time.Time), active: make(map[string]*active)}
	g.proxy = &httputil.ReverseProxy{
		Transport: secureTransport(),
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(upstream)
			p.Out.Host = g.host
			// Forward an allowlist instead of trying to enumerate spoofable headers.
			p.Out.Header = make(http.Header)
			p.Out.Header.Set("Origin", c.Origin)
			if p.In.URL.Path == "/session/ha" {
				p.Out.Header.Set(AssertionHeader, p.In.Header.Get(AssertionHeader))
				p.Out.URL.Path = c.SessionPath
				p.Out.URL.RawPath = ""
				p.Out.URL.RawQuery = p.In.URL.RawQuery
			} else if p.In.URL.Path == "/api/websocket" {
				for _, key := range []string{"Authorization", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
					if value := p.In.Header.Get(key); value != "" {
						p.Out.Header.Set(key, value)
					}
				}
				p.Out.Header.Set("Connection", "Upgrade")
				p.Out.Header.Set("Upgrade", "websocket")
			} else {
				for _, key := range []string{"Authorization", "Content-Type", "Accept"} {
					if value := p.In.Header.Get(key); value != "" {
						p.Out.Header.Set(key, value)
					}
				}
			}
		},
		ModifyResponse: func(r *http.Response) error {
			if r.StatusCode >= 300 && r.StatusCode <= 399 {
				location, err := url.Parse(r.Header.Get("Location"))
				// Only an explicitly enabled OAuth callback may redirect, to
				// this exact public origin. No external token destination.
				if mediaArtworkPath.MatchString(r.Request.URL.Path) || !c.EnableHALogin || err != nil || location.Scheme != "https" || location.Host != g.host || location.Path != "/" || !validCallback(location.Query()) {
					return errors.New("upstream redirects are forbidden")
				}
			}
			r.Header.Del("Set-Cookie")
			r.Header.Del("Access-Control-Allow-Origin")
			r.Header.Set("Cache-Control", "no-store")
			r.Header.Set("Referrer-Policy", "no-referrer")
			if r.Request.URL.Path == c.SessionPath && r.Request.URL.RawQuery == "revoke=1" && r.StatusCode == http.StatusNoContent {
				g.revoke(hash(r.Request.Header.Get(AssertionHeader)))
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Home Assistant unavailable", 502)
		},
	}
	return g, nil
}

func hash(raw string) string { sum := sha256.Sum256([]byte(raw)); return hex.EncodeToString(sum[:]) }
func (g *Gateway) prune() {
	now := time.Now()
	for key, expires := range g.revoked {
		if !expires.After(now) {
			delete(g.revoked, key)
		}
	}
	for key, state := range g.active {
		if !state.expires.After(now) && len(state.cancels) == 0 {
			delete(g.active, key)
		}
	}
}
func (g *Gateway) isRevoked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune()
	_, denied := g.revoked[key]
	return denied
}
func (g *Gateway) revoke(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if state := g.active[key]; state != nil {
		g.revoked[key] = state.expires
		for _, cancel := range state.cancels {
			cancel()
		}
	}
}
func (g *Gateway) register(key string, expires time.Time, cancel context.CancelFunc) (func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune()
	if _, denied := g.revoked[key]; denied {
		return nil, false
	}
	state := g.active[key]
	if state == nil {
		if len(g.active)+len(g.revoked) >= 128 {
			return nil, false
		}
		state = &active{expires: expires, cancels: make(map[uint64]context.CancelFunc)}
		g.active[key] = state
	}
	g.next++
	id := g.next
	state.cancels[id] = cancel
	return func() { g.mu.Lock(); defer g.mu.Unlock(); delete(state.cancels, id) }, true
}

func validCallback(query url.Values) bool {
	return len(query) == 2 && len(query["code"]) == 1 && len(query["state"]) == 1 &&
		len(query.Get("code")) > 0 && len(query.Get("code")) <= 4096 && len(query.Get("state")) > 0 && len(query.Get("state")) <= 256
}

func (g *Gateway) loginRoute(r *http.Request) bool {
	p := r.URL.Path
	if p == "/auth/authorize" {
		q := r.URL.Query()
		return r.Method == "GET" && len(q) == 4 && len(q["response_type"]) == 1 && q.Get("response_type") == "code" &&
			len(q["client_id"]) == 1 && q.Get("client_id") == g.config.Origin+"/" &&
			len(q["redirect_uri"]) == 1 && q.Get("redirect_uri") == g.config.Origin+"/" &&
			len(q["state"]) == 1 && len(q.Get("state")) > 0 && len(q.Get("state")) <= 256
	}
	if r.URL.RawQuery == "" {
		if p == "/auth/providers" {
			return r.Method == "GET"
		}
		if p == "/auth/token" || p == "/auth/revoke" || p == "/auth/login_flow" {
			return r.Method == "POST"
		}
		if strings.HasPrefix(p, "/auth/login_flow/") {
			id := strings.TrimPrefix(p, "/auth/login_flow/")
			return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == "" && (r.Method == "GET" || r.Method == "POST")
		}
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		return false
	}
	for _, prefix := range []string{"/frontend_latest/", "/frontend_es5/", "/static/", "/translations/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return p == "/manifest.json" || p == "/favicon.ico"
}

func validProtectedHeader(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	// The compact bytes identify revocations. Reject alternate encodings of the
	// same signature, including padding, whitespace and unused base64 bits.
	for _, part := range parts {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(part) == 0 || base64.RawURLEncoding.EncodeToString(decoded) != part {
			return false
		}
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Algorithm string          `json:"alg"`
		KeyID     string          `json:"kid"`
		Critical  json.RawMessage `json:"crit"`
	}
	if json.Unmarshal(data, &header) != nil || header.Algorithm != "RS256" || len(header.KeyID) == 0 || len(header.KeyID) > 256 {
		return false
	}
	return len(header.Critical) == 0 || string(header.Critical) == "[]" || string(header.Critical) == "null"
}

func validNotBefore(raw json.RawMessage, now int64) bool {
	if len(raw) == 0 {
		return true
	}
	var timestamp int64
	return string(raw) != "null" && json.Unmarshal(raw, &timestamp) == nil && timestamp <= now
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deny := func(message string, status int) {
		if r.URL.Path == "/session/ha" {
			stopSessionBody(w, r)
		}
		http.Error(w, message, status)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		w.WriteHeader(200)
		return
	}
	if r.Host != g.host {
		deny("unrecognized host", 403)
		return
	}
	origins := r.Header.Values("Origin")
	// A link or identity-provider redirect may navigate from another site to
	// the dashboard. Only the top-level HTML entry point gets this exception;
	// it still requires the signed, mapped assertion below. API calls, embeds
	// and writes retain the cross-site rejection.
	modes, destinations := r.Header.Values("Sec-Fetch-Mode"), r.Header.Values("Sec-Fetch-Dest")
	documentNavigation := r.Method == http.MethodGet && r.URL.Path == "/" &&
		len(modes) == 1 && modes[0] == "navigate" && len(destinations) == 1 && destinations[0] == "document"
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != g.config.Origin) ||
		(r.Header.Get("Sec-Fetch-Site") == "cross-site" && !documentNavigation) {
		deny("unrecognized origin", 403)
		return
	}
	if path.Clean(r.URL.Path) != r.URL.Path || strings.Contains(r.URL.Path, "\\") || r.URL.EscapedPath() != r.URL.Path {
		deny("404 page not found", http.StatusNotFound)
		return
	}
	assertions := r.Header.Values(AssertionHeader)
	if len(assertions) != 1 || len(assertions[0]) == 0 || len(assertions[0]) > 16384 {
		deny("signed Access assertion required", 401)
		return
	}
	if !validProtectedHeader(assertions[0]) {
		deny("invalid protected header", 401)
		return
	}
	token, err := g.verifier.Verify(r.Context(), assertions[0])
	if err != nil {
		deny("invalid Access assertion", 401)
		return
	}
	var c claims
	now := time.Now().Unix()
	if token.Claims(&c) != nil || c.Subject == nil || c.Type != "app" || c.IssuedAt <= 0 || c.IssuedAt > now ||
		c.Expires <= now || c.Expires-c.IssuedAt <= 0 || c.Expires-c.IssuedAt > int64(g.config.MaxAssertionLifetimeSeconds) ||
		!validNotBefore(c.NotBefore, now) {
		deny("invalid Access claims", 401)
		return
	}
	network := g.config.AllowTrustedNetwork && *c.Subject == "" && len(c.Email) == 0 && len(c.CommonName) == 0
	var email string
	owner := *c.Subject != "" && len(c.CommonName) == 0 && json.Unmarshal(c.Email, &email) == nil && email == g.config.Email
	if !network && !owner {
		deny("Access identity not mapped", 403)
		return
	}
	key := hash(assertions[0])
	if g.isRevoked(key) {
		deny("session revoked", 401)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/session" && r.URL.RawQuery == "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"contract_version": 1, "expires_at": c.Expires})
		return
	}
	if (r.Method == "GET" || r.Method == "HEAD") && (r.URL.RawQuery == "" || (g.config.EnableHALogin && r.URL.Path == "/" && validCallback(r.URL.Query()))) {
		if data, ok := g.files[r.URL.Path]; ok {
			ext := path.Ext(r.URL.Path)
			if r.URL.Path == "/" {
				ext = ".html"
			}
			w.Header().Set("Content-Type", mime.TypeByExtension(ext))
			policy := g.config.ContentSecurityPolicy
			if policy == "" {
				policy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
			}
			w.Header().Set("Content-Security-Policy", policy)
			if r.Method != "HEAD" {
				_, _ = w.Write(data)
			}
			return
		}
	}
	exchange := r.URL.Path == "/session/ha" && r.Method == "POST" &&
		(r.URL.RawQuery == "" || r.URL.RawQuery == "revoke=1")
	websocket := r.URL.Path == "/api/websocket" && r.Method == "GET" && r.URL.RawQuery == "" &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	login := g.config.EnableHALogin && g.loginRoute(r)
	artwork := g.config.EnableMediaArtwork && mediaArtworkRoute(r)
	if (!exchange && !websocket && !login && !artwork) || ((exchange || websocket || r.Method == "POST") && len(origins) != 1) {
		deny("404 page not found", http.StatusNotFound)
		return
	}
	if login && r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
	}
	deadline := time.Now().Add(g.config.connectionLifetime())
	if artwork {
		if artworkDeadline := time.Now().Add(mediaArtworkTimeout); artworkDeadline.Before(deadline) {
			deadline = artworkDeadline
		}
	}
	if token.Expiry.Before(deadline) {
		deadline = token.Expiry
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	// Revocation itself must not be cancelled before its 204 response is sent.
	trackingCancel := cancel
	if exchange && r.URL.RawQuery == "revoke=1" {
		trackingCancel = func() {}
	}
	unregister, ok := g.register(key, token.Expiry, trackingCancel)
	if !ok {
		deny("session limit or revocation", 429)
		return
	}
	defer unregister()
	if exchange && !normalizeSessionBody(ctx, w, r) {
		return
	}
	g.proxy.ServeHTTP(w, r.WithContext(ctx))
}
