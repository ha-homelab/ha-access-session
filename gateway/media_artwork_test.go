package gateway

import (
	"bytes"
	"crypto/rsa"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const artworkURL = "/api/media_player_proxy/media_player.saved_id"

type artworkServer struct {
	gateway *Gateway
	key     *rsa.PrivateKey
	server  *httptest.Server
	client  *http.Client
}

func newArtworkServer(t *testing.T, upstream http.Handler, login bool) artworkServer {
	t.Helper()
	g, key := fixture(t, upstream)
	c := g.config
	c.EnableMediaArtwork = true
	c.EnableHALogin = login
	g, err := newWithVerifier(c, g.verifier)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g)
	t.Cleanup(server.Close)
	return artworkServer{g, key, server, &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (s artworkServer) request(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, s.server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = config().Origin[len("https://"):]
	r.Header.Set(AssertionHeader, signed(t, s.key, claimsMap()))
	r.Header.Set("Authorization", "Bearer synthetic")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func (s artworkServer) send(t *testing.T, r *http.Request) (*http.Response, []byte) {
	t.Helper()
	response, err := s.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

func TestMediaArtworkOptInAndAuthenticatedProxy(t *testing.T) {
	var hits atomic.Int32
	var imageBytes bytes.Buffer
	if err := png.Encode(&imageBytes, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	s := newArtworkServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "GET" || !mediaArtworkPath.MatchString(r.URL.Path) || r.URL.RawQuery != "" || r.Host != "dashboard.example.invalid" || r.Header.Get("Origin") != config().Origin {
			t.Error("incorrect artwork request")
		}
		if r.Header.Get("Authorization") == "Bearer invalid-ha-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer synthetic" || r.Header.Get("Accept") != "image/png" {
			t.Error("allowlisted credentials or Accept were not preserved")
		}
		for _, header := range []string{AssertionHeader, "Cookie", "Cf-Access-Authenticated-User-Email", "X-Forwarded-User", "X-Forwarded-For", "Forwarded", "Impersonate-User", "Range", "Sec-Fetch-Site"} {
			if r.Header.Get(header) != "" {
				t.Errorf("artwork forwarded unapproved header %s", header)
			}
		}
		if body, _ := io.ReadAll(r.Body); len(body) != 0 {
			t.Error("artwork forwarded a body")
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Set-Cookie", "untrusted=value")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(imageBytes.Bytes())
	}), false)
	s.gateway.config.EnableMediaArtwork = false
	if response, _ := s.send(t, s.request(t, "GET", artworkURL, nil)); response.StatusCode != 404 || hits.Load() != 0 {
		t.Fatal("artwork is not disabled by default")
	}
	s.gateway.config.EnableMediaArtwork = true
	for _, path := range []string{artworkURL, "/api/media_player_proxy/media_player." + strings.Repeat("a", 137)} {
		r := s.request(t, "GET", path, nil)
		r.Header.Set("Accept", "image/png")
		for _, header := range []string{"Cookie", "Cf-Access-Authenticated-User-Email", "X-Forwarded-User", "X-Forwarded-For", "Forwarded", "Impersonate-User", "Range"} {
			r.Header.Set(header, "untrusted")
		}
		response, body := s.send(t, r)
		if response.StatusCode != 200 || !bytes.Equal(body, imageBytes.Bytes()) || response.Header.Get("Content-Type") != "image/png" {
			t.Fatal("canonical image was not preserved")
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("artwork response bypassed common security headers")
		}
	}
	r := s.request(t, "GET", artworkURL, nil)
	r.Header.Set("Authorization", "Bearer invalid-ha-token")
	if response, _ := s.send(t, r); response.StatusCode != 401 {
		t.Fatal("Access admission replaced HA authentication")
	}
	r = s.request(t, "GET", artworkURL, nil)
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Origin", config().Origin)
	r.Header.Set("Accept", "image/png")
	if response, _ := s.send(t, r); response.StatusCode != 200 {
		t.Fatal("exact Origin was rejected without Fetch Metadata")
	}
}

func TestMediaArtworkRejectsNoncanonicalAndUnauthorizedRequests(t *testing.T) {
	var hits atomic.Int32
	s := newArtworkServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }), true)
	for _, path := range []string{
		artworkURL + "?", artworkURL + "?token=synthetic", artworkURL + "/", artworkURL + "/extra",
		"/api/media_player_proxy/media_player.", "/api/media_player_proxy/media_player." + strings.Repeat("a", 138),
		"/api/media_player_proxy/media_player.Saved", "/api/media_player_proxy/media_player.with-dash",
		"/api/media_player_proxy/light.saved_id", "/api/media_player_proxy/http://evil.example.invalid/image",
		"/api/media_player_proxy/media_player.%73aved_id", "/api/media_player_proxy/media_player%2esaved_id",
		"/api%2fmedia_player_proxy/media_player.saved_id", "/api/media_player_proxy//media_player.saved_id",
		"/api/media_player_proxy/../media_player_proxy/media_player.saved_id", "/api/states", "/api/services/light/turn_on",
	} {
		t.Run(path, func(t *testing.T) {
			if response, _ := s.send(t, s.request(t, "GET", path, nil)); response.StatusCode != 404 {
				t.Fatalf("noncanonical route returned %d", response.StatusCode)
			}
		})
	}
	for _, method := range []string{"HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if response, _ := s.send(t, s.request(t, method, artworkURL, nil)); response.StatusCode != 404 {
			t.Errorf("method %s returned %d", method, response.StatusCode)
		}
	}
	cases := []struct {
		name string
		edit func(*http.Request)
	}{
		{"no bearer", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"empty bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }},
		{"basic credentials", func(r *http.Request) { r.Header.Set("Authorization", "Basic synthetic") }},
		{"duplicate bearer", func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }},
		{"merged bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer a, Bearer b") }},
		{"oversized bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 8193)) }},
		{"wrong origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.invalid") }},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"duplicate origin", func(r *http.Request) {
			r.Header.Add("Origin", config().Origin)
			r.Header.Add("Origin", config().Origin)
		}},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"same site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
		{"no origin evidence", func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }},
		{"duplicate fetch metadata", func(r *http.Request) { r.Header.Add("Sec-Fetch-Site", "same-origin") }},
		{"wrong host", func(r *http.Request) { r.Host = "evil.example.invalid" }},
		{"no assertion", func(r *http.Request) { r.Header.Del(AssertionHeader) }},
		{"forged assertion", func(r *http.Request) { r.Header.Set(AssertionHeader, "forged") }},
		{"duplicate assertion", func(r *http.Request) { r.Header.Add(AssertionHeader, r.Header.Get(AssertionHeader)) }},
		{"expired assertion", func(r *http.Request) {
			c := claimsMap()
			c["exp"] = time.Now().Add(-time.Minute).Unix()
			r.Header.Set(AssertionHeader, signed(t, s.key, c))
		}},
		{"unmapped assertion", func(r *http.Request) {
			c := claimsMap()
			c["email"] = "other@example.invalid"
			r.Header.Set(AssertionHeader, signed(t, s.key, c))
		}},
		{"body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("body")); r.ContentLength = 4 }},
		{"chunked body", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("body"))
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := s.request(t, "GET", artworkURL, nil)
			tc.edit(r)
			if response, _ := s.send(t, r); response.StatusCode < 400 {
				t.Fatalf("invalid request returned %d", response.StatusCode)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatal("rejected request reached HA")
	}
}

func TestMediaArtworkRejectsEveryRedirectWithHALoginEnabled(t *testing.T) {
	var location atomic.Value
	var status atomic.Int32
	s := newArtworkServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location.Load().(string))
		w.WriteHeader(int(status.Load()))
	}), true)
	for _, target := range []string{"https://evil.example.invalid/image", "/auth/authorize", config().Origin + "/?code=synthetic&state=nonce"} {
		location.Store(target)
		for _, code := range []int{301, 302, 303, 304, 307, 308} {
			status.Store(int32(code))
			response, _ := s.send(t, s.request(t, "GET", artworkURL, nil))
			if response.StatusCode != 502 || response.Header.Get("Location") != "" {
				t.Fatalf("artwork redirect %d escaped: %d", code, response.StatusCode)
			}
		}
	}
}

func TestMediaArtworkDeadlineAndRevocation(t *testing.T) {
	for _, mode := range []string{"artwork deadline", "shorter connection deadline", "revocation"} {
		t.Run(mode, func(t *testing.T) {
			started, ended := make(chan struct{}), make(chan struct{})
			s := newArtworkServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == SessionPath {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				close(started)
				<-r.Context().Done()
				close(ended)
			}), false)
			if mode == "shorter connection deadline" {
				s.gateway.config.MaxConnectionSeconds = 1
			}
			r := s.request(t, "GET", artworkURL, nil)
			raw := r.Header.Get(AssertionHeader)
			completed := make(chan int, 1)
			begin := time.Now()
			go func() {
				response, err := s.client.Do(r)
				if err != nil {
					completed <- 0
					return
				}
				defer response.Body.Close()
				completed <- response.StatusCode
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("artwork did not reach HA")
			}
			if mode == "revocation" {
				revoke := s.request(t, "POST", "/session/ha?revoke=1", nil)
				revoke.Header.Set(AssertionHeader, raw)
				revoke.Header.Set("Origin", config().Origin)
				if response, _ := s.send(t, revoke); response.StatusCode != 204 {
					t.Fatal("session revocation failed")
				}
			}
			select {
			case code := <-completed:
				if code != 502 {
					t.Fatalf("cancelled artwork returned %d", code)
				}
			case <-time.After(12 * time.Second):
				t.Fatal("artwork outlived its deadline")
			}
			select {
			case <-ended:
			case <-time.After(time.Second):
				t.Fatal("upstream artwork request was not cancelled")
			}
			elapsed := time.Since(begin)
			if mode == "artwork deadline" && (elapsed < 9*time.Second || elapsed > 12*time.Second) {
				t.Fatalf("incorrect 10-second artwork ceiling: %v", elapsed)
			}
			if mode == "shorter connection deadline" && elapsed > 3*time.Second {
				t.Fatal("artwork bypassed the shorter connection deadline")
			}
			if mode == "revocation" {
				after := s.request(t, "GET", artworkURL, nil)
				after.Header.Set(AssertionHeader, raw)
				if response, _ := s.send(t, after); response.StatusCode != 401 {
					t.Fatal("revoked assertion reused for artwork")
				}
			}
		})
	}
}
