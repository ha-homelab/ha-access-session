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

var sessionDenials = []struct {
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
}

func deniedSessionRequest(t *testing.T, target, token, denial string, body io.Reader) *http.Request {
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
	default:
		t.Fatal("unknown denial case")
	}
	return r
}

func TestSessionDenialDoesNotDrainUnfinishedHTTP1Body(t *testing.T) {
	var hits atomic.Int32
	g, key := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	token := signed(t, key, claimsMap())
	server := httptest.NewServer(g)
	defer server.Close()
	for _, framing := range []string{"Transfer-Encoding: chunked", "Content-Length: 1"} {
		for _, tc := range sessionDenials {
			t.Run(framing+"/"+tc.name, func(t *testing.T) {
				r := deniedSessionRequest(t, server.URL, token, tc.name, nil)
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

func TestSessionDenialKeepsOtherHTTP2StreamsUsable(t *testing.T) {
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
	for _, tc := range sessionDenials {
		t.Run(tc.name, func(t *testing.T) {
			body, writer := io.Pipe()
			defer body.Close()
			defer writer.Close()
			r := deniedSessionRequest(t, server.URL, token, tc.name, body)
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
	if hits.Load() != int32(len(sessionDenials)) {
		t.Fatalf("upstream hits=%d, want only the valid follow-up exchanges", hits.Load())
	}
}
