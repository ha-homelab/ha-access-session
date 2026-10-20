package gateway

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"
)

var gatewayAdmissionDenials = []struct {
	name   string
	status int
}{
	{"missing-assertion", http.StatusUnauthorized},
	{"invalid-assertion", http.StatusUnauthorized},
	{"wrong-host", http.StatusForbidden},
	{"wrong-origin", http.StatusForbidden},
	{"duplicate-origin", http.StatusForbidden},
	{"missing-origin", http.StatusNotFound},
	{"wrong-query", http.StatusNotFound},
	{"wrong-method", http.StatusNotFound},
	{"unknown-path", http.StatusNotFound},
	{"unknown-path-missing-assertion", http.StatusUnauthorized},
	{"disabled-oauth", http.StatusNotFound},
	{"disabled-artwork", http.StatusBadRequest},
	{"healthz-body", http.StatusBadRequest},
	{"session-get-body", http.StatusBadRequest},
	{"static-get-body", http.StatusBadRequest},
	{"static-head-body", http.StatusBadRequest},
	{"websocket-body", http.StatusBadRequest},
}

func deniedGatewayRequest(t *testing.T, target, token, denial string, body io.Reader) *http.Request {
	t.Helper()
	r := sessionRequest(t, target+"/session/ha", token, body)
	switch denial {
	case "missing-assertion":
		r.Header.Del(AssertionHeader)
	case "invalid-assertion":
		r.Header.Set(AssertionHeader, "invalid")
	case "wrong-host":
		r.Host = "other.example.invalid"
	case "wrong-origin":
		r.Header.Set("Origin", "https://other.example.invalid")
	case "duplicate-origin":
		r.Header.Add("Origin", config().Origin)
	case "missing-origin":
		r.Header.Del("Origin")
	case "wrong-query":
		r.URL.RawQuery = "user_id=other"
	case "wrong-method":
		r.Method = http.MethodPut
	case "unknown-path":
		r.URL.Path = "/unrecognized"
	case "unknown-path-missing-assertion":
		r.URL.Path = "/unrecognized"
		r.Header.Del(AssertionHeader)
	case "disabled-oauth":
		r.URL.Path = "/auth/token"
	case "disabled-artwork":
		r.URL.Path = "/api/media_player_proxy/media_player.synthetic"
		r.Method = http.MethodGet
	case "healthz-body":
		r.URL.Path = "/healthz"
		r.Method = http.MethodGet
		r.Header.Del(AssertionHeader)
	case "session-get-body":
		r.URL.Path = "/session"
		r.Method = http.MethodGet
	case "static-get-body", "static-head-body":
		r.URL.Path = "/"
		r.Method = http.MethodGet
		if denial == "static-head-body" {
			r.Method = http.MethodHead
		}
	case "websocket-body":
		r.URL.Path = "/api/websocket"
		r.Method = http.MethodGet
	default:
		t.Fatal("unknown denial case")
	}
	return r
}

func TestGatewayDenialDoesNotDrainUnfinishedHTTP1Body(t *testing.T) {
	var hits atomic.Int32
	g, key := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	token := signed(t, key, claimsMap())
	server := httptest.NewServer(g)
	defer server.Close()
	for _, framing := range []string{"Transfer-Encoding: chunked", "Content-Length: 1", "Transfer-Encoding: chunked\r\nTrailer: X-Untrusted"} {
		for _, tc := range gatewayAdmissionDenials {
			t.Run(framing+"/"+tc.name, func(t *testing.T) {
				r := deniedGatewayRequest(t, server.URL, token, tc.name, nil)
				if tc.name == "websocket-body" {
					r.Header.Set("Connection", "Upgrade")
					r.Header.Set("Upgrade", "websocket")
					r.Header.Set("Sec-WebSocket-Version", "13")
					r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				}
				conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(sessionBodyTimeout + time.Second))
				if _, err = fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n",
					r.Method, r.URL.RequestURI(), r.Host, framing); err != nil {
					t.Fatal(err)
				}
				if err = r.Header.Write(conn); err != nil {
					t.Fatal(err)
				}
				// Deliberately send neither the promised byte nor a terminal chunk.
				if _, err = io.WriteString(conn, "\r\n"); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(conn)
				response, err := http.ReadResponse(reader, r)
				if err != nil {
					t.Fatalf("denial waited for the rejected request body: %v", err)
				}
				defer response.Body.Close()
				if _, err = io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != tc.status || !response.Close {
					t.Fatalf("status=%d close=%t, want status=%d and closed connection",
						response.StatusCode, response.Close, tc.status)
				}
				if _, err = reader.ReadByte(); err != io.EOF {
					t.Fatalf("rejected connection remains open: %v", err)
				}
			})
		}
	}
	if hits.Load() != 0 {
		t.Fatal("rejected request reached upstream")
	}
}

func TestBodylessLocalRoutesRealHTTP(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			var hits atomic.Int32
			g, key := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
			}))
			token := signed(t, key, claimsMap())
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if (r.ProtoMajor == 2) != h2 || r.ContentLength != 0 {
					t.Errorf("unexpected request: protocol=%s length=%d", r.Proto, r.ContentLength)
				}
				// A normal HTTP/2 body can be a non-NoBody stream at length zero.
				g.ServeHTTP(w, r)
			}))
			server.EnableHTTP2 = h2
			if h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := server.Client()
			client.Timeout = sessionBodyTimeout + time.Second
			for _, tc := range []struct{ method, path string }{
				{http.MethodGet, "/healthz"},
				{http.MethodGet, "/session"},
				{http.MethodGet, "/"},
				{http.MethodHead, "/"},
			} {
				t.Run(tc.method+tc.path, func(t *testing.T) {
					r := sessionRequest(t, server.URL+tc.path, token, http.NoBody)
					r.Method = tc.method
					if tc.path == "/healthz" {
						r.Header.Del(AssertionHeader)
					}
					response, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil || response.StatusCode != http.StatusOK || response.Close {
						t.Fatalf("status=%d close=%t error=%v", response.StatusCode, response.Close, err)
					}
					if tc.method == http.MethodHead && len(body) != 0 {
						t.Fatal("HEAD returned a body")
					}
				})
			}
			if hits.Load() != 0 {
				t.Fatal("local response reached upstream")
			}
		})
	}
}

func TestGatewayDenialKeepsOtherHTTP2StreamsUsable(t *testing.T) {
	var hits atomic.Int32
	g, key := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	token := signed(t, key, claimsMap())
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = sessionBodyTimeout + time.Second
	for _, tc := range gatewayAdmissionDenials {
		t.Run(tc.name, func(t *testing.T) {
			body, writer := io.Pipe()
			defer body.Close()
			defer writer.Close()
			r := deniedGatewayRequest(t, server.URL, token, tc.name, body)
			response, err := client.Do(r)
			if err != nil {
				t.Fatalf("denial waited for the rejected request body: %v", err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			writer.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.ProtoMajor != 2 || response.StatusCode != tc.status {
				t.Fatalf("protocol=%s status=%d, want HTTP/2 and %d",
					response.Proto, response.StatusCode, tc.status)
			}
			// The same connection must still accept a valid empty exchange.
			reused := false
			next := sessionRequest(t, server.URL+"/session/ha", token, http.NoBody)
			next = next.WithContext(httptrace.WithClientTrace(next.Context(), &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
			}))
			healthy, err := client.Do(next)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, healthy.Body)
			healthy.Body.Close()
			if err != nil || healthy.StatusCode != http.StatusNoContent || !reused {
				t.Fatalf("next stream status=%d reused=%t error=%v",
					healthy.StatusCode, reused, err)
			}
		})
	}
	if hits.Load() != int32(len(gatewayAdmissionDenials)) {
		t.Fatalf("upstream hits=%d, want only the valid follow-up exchanges", hits.Load())
	}
}
