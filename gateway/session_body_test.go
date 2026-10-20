package gateway

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sessionRequest(t *testing.T, target, token string, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, target, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "dashboard.example.invalid"
	r.Header.Set("Origin", config().Origin)
	r.Header.Set(AssertionHeader, token)
	r.Header.Set("Cookie", "synthetic=not-forwarded")
	r.Header.Set("Authorization", "Bearer not-forwarded")
	return r
}

func TestSessionBodyRealHTTP(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, name := range []string{"known-empty", "unknown-empty", "delayed-empty", "known-byte", "unknown-byte", "revoke-empty", "trailer-empty"} {
			t.Run(fmt.Sprintf("http2=%t/%s", h2, name), func(t *testing.T) {
				var hits atomic.Int32
				g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil || len(body) != 0 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
						len(r.Trailer) != 0 || r.Header.Get("Content-Length") != "0" {
						t.Errorf("upstream body not normalized: len=%d length=%d encoding=%v error=%v",
							len(body), r.ContentLength, r.TransferEncoding, err)
					}
					if r.URL.Path != SessionPath || r.Header.Get(AssertionHeader) == "" || r.Header.Get("Origin") != config().Origin {
						t.Error("session routing or identity changed")
					}
					if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
						t.Error("unapproved header reached upstream")
					}
					if (r.URL.RawQuery == "revoke=1") != (name == "revoke-empty") {
						t.Errorf("unexpected query %q", r.URL.RawQuery)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if (r.ProtoMajor == 2) != h2 {
						t.Errorf("wrong protocol %s", r.Proto)
					}
					if name == "unknown-empty" || name == "delayed-empty" || name == "revoke-empty" {
						if r.ContentLength != -1 || (len(r.TransferEncoding) != 0) == h2 {
							t.Errorf("test did not send unknown-length body: length=%d encoding=%v", r.ContentLength, r.TransferEncoding)
						}
					}
					g.ServeHTTP(w, r)
				}))
				server.EnableHTTP2 = h2
				if h2 {
					server.StartTLS()
				} else {
					server.Start()
				}
				defer server.Close()
				var body io.Reader
				switch name {
				case "known-empty":
					body = http.NoBody
				case "known-byte":
					body = strings.NewReader("x")
				case "unknown-byte":
					body = io.NopCloser(strings.NewReader("x"))
				case "delayed-empty":
					reader, writer := io.Pipe()
					defer reader.Close()
					timer := time.AfterFunc(50*time.Millisecond, func() { _ = writer.Close() })
					defer timer.Stop()
					defer writer.Close()
					body = reader
				default:
					body = io.NopCloser(strings.NewReader(""))
				}
				target := server.URL + "/session/ha"
				if name == "revoke-empty" {
					target += "?revoke=1"
				}
				r := sessionRequest(t, target, signed(t, k, claimsMap()), body)
				if name == "trailer-empty" {
					r.Trailer = http.Header{"X-Unapproved": []string{"value"}}
				}
				client := server.Client()
				client.Timeout = 4 * time.Second
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				_, _ = io.Copy(io.Discard, response.Body)
				if strings.HasSuffix(name, "-byte") || name == "trailer-empty" {
					if response.StatusCode != http.StatusBadRequest || hits.Load() != 0 {
						t.Fatalf("nonempty request: status=%d upstream hits=%d", response.StatusCode, hits.Load())
					}
				} else if response.StatusCode != http.StatusNoContent || hits.Load() != 1 {
					t.Fatalf("empty request: status=%d upstream hits=%d", response.StatusCode, hits.Load())
				}
			})
		}
	}
}

func TestSessionBodyRejectsInvalidAndStalledHTTP1(t *testing.T) {
	for _, tc := range []struct {
		name, headers, wireBody string
		status                  int
	}{
		{"malformed-chunk", "", "not-hex\r\n", http.StatusBadRequest},
		{"declared-trailer", "Trailer: X-Unapproved\r\n", "0\r\nX-Unapproved: value\r\n\r\n", http.StatusBadRequest},
		{"undeclared-trailer", "", "0\r\nX-Unapproved: value\r\n\r\n", http.StatusBadRequest},
		{"byte-without-eof", "", "1\r\nx\r\n", http.StatusBadRequest},
		{"stalled-empty", "", "", http.StatusRequestTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			server := httptest.NewServer(g)
			defer server.Close()
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(sessionBodyTimeout + 2*time.Second))
			raw := fmt.Sprintf("POST /session/ha HTTP/1.1\r\nHost: dashboard.example.invalid\r\nOrigin: %s\r\n%s: %s\r\nTransfer-Encoding: chunked\r\n%s\r\n%s",
				config().Origin, AssertionHeader, signed(t, k, claimsMap()), tc.headers, tc.wireBody)
			started := time.Now()
			if _, err = io.WriteString(conn, raw); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
			if response.StatusCode != tc.status || hits.Load() != 0 || !response.Close {
				t.Fatalf("status=%d upstream hits=%d close=%t", response.StatusCode, hits.Load(), response.Close)
			}
			if time.Since(started) > sessionBodyTimeout+time.Second {
				t.Fatal("body validation/drain exceeded deadline")
			}
			if _, err = reader.ReadByte(); err != io.EOF {
				t.Fatalf("rejected connection was not closed: %v", err)
			}
		})
	}
}

func TestSessionBodyRejectsStalledHTTP2(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	body, writer := io.Pipe()
	defer body.Close()
	defer writer.Close()
	r := sessionRequest(t, server.URL+"/session/ha", signed(t, k, claimsMap()), body)
	client := server.Client()
	client.Timeout = sessionBodyTimeout + 2*time.Second
	started := time.Now()
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusRequestTimeout || hits.Load() != 0 {
		t.Fatalf("protocol=%s status=%d upstream hits=%d", response.Proto, response.StatusCode, hits.Load())
	}
	if time.Since(started) > sessionBodyTimeout+time.Second {
		t.Fatal("HTTP/2 body validation exceeded deadline")
	}
}

func TestSessionBodyKeepsBoundaryChecks(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	server := httptest.NewServer(g)
	defer server.Close()
	token := signed(t, k, claimsMap())
	for _, tc := range []struct {
		name, query, origin, assertion string
		status                         int
	}{
		{"wrong-origin", "", "https://other.example.invalid", token, http.StatusForbidden},
		{"missing-origin", "", "", token, http.StatusNotFound},
		{"invalid-assertion", "", config().Origin, "invalid", http.StatusUnauthorized},
		{"unapproved-query", "?user_id=other", config().Origin, token, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := sessionRequest(t, server.URL+"/session/ha"+tc.query, tc.assertion, io.NopCloser(strings.NewReader("")))
			r.Header.Set("Origin", tc.origin)
			if tc.origin == "" {
				r.Header.Del("Origin")
			}
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.status || hits.Load() != 0 {
				t.Fatalf("status=%d upstream hits=%d", response.StatusCode, hits.Load())
			}
		})
	}
}

func TestSessionBodyDoesNotChangeOAuthPayload(t *testing.T) {
	const payload = "grant_type=authorization_code&code=synthetic"
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != payload || r.URL.Path != "/auth/token" {
			t.Error("OAuth payload changed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	g.config.EnableHALogin = true
	server := httptest.NewServer(g)
	defer server.Close()
	r := sessionRequest(t, server.URL+"/auth/token", signed(t, k, claimsMap()), io.NopCloser(strings.NewReader(payload)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || hits.Load() != 1 {
		t.Fatalf("status=%d upstream hits=%d", response.StatusCode, hits.Load())
	}
}

func TestSessionBodyRequiresReadDeadlineSupport(t *testing.T) {
	var hits atomic.Int32
	g, k := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	r := sessionRequest(t, config().Origin+"/session/ha", signed(t, k, claimsMap()), io.NopCloser(strings.NewReader("")))
	w := httptest.NewRecorder() // Unlike a real server response, this has no read deadline.
	g.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || hits.Load() != 0 {
		t.Fatalf("unbounded reader was accepted: status=%d upstream hits=%d", w.Code, hits.Load())
	}
}
