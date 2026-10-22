package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Only the deadline capability of the net/http adapter is replaced. Production
// body admission runs unchanged; this never opens a listener or proxy connection.
type fuzzDeadlineWriter struct{ *httptest.ResponseRecorder }

func (w fuzzDeadlineWriter) SetReadDeadline(time.Time) error { return nil }

func FuzzSessionBody(f *testing.F) {
	f.Add([]byte{}, int64(0), "", false, false)
	f.Add([]byte{}, int64(-1), "chunked", false, false)
	f.Add([]byte("unexpected"), int64(-1), "chunked", false, false)
	f.Add([]byte{}, int64(0), "", true, false)
	f.Add([]byte{}, int64(0), "", false, true)
	f.Fuzz(func(t *testing.T, body []byte, length int64, transfer string, trailer, cancelled bool) {
		if len(body) > 8192 || len(transfer) > 256 {
			t.Skip()
		}
		request := &http.Request{ProtoMajor: 1, Header: make(http.Header), ContentLength: length, Body: io.NopCloser(bytes.NewReader(body))}
		if transfer != "" {
			request.TransferEncoding = []string{transfer}
		}
		if trailer {
			request.Trailer = http.Header{"X-Fuzz": []string{"value"}}
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if cancelled {
			cancel()
		}
		recorder := httptest.NewRecorder()
		admitted := normalizeSessionBody(ctx, fuzzDeadlineWriter{recorder}, request)
		expected := len(body) == 0 && length <= 0 && (transfer == "" || transfer == "chunked") && !trailer && !cancelled
		if admitted != expected {
			t.Fatalf("body admission=%v, expected %v", admitted, expected)
		}
		if admitted {
			if request.Body != http.NoBody || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 {
				t.Fatal("accepted request retained ambiguous framing")
			}
			if !normalizeSessionBody(ctx, fuzzDeadlineWriter{httptest.NewRecorder()}, request) {
				t.Fatal("normalization is not idempotent")
			}
		} else if recorder.Code < 400 {
			t.Fatal("rejected request lacks error status")
		}
	})
}

func FuzzArtworkAdmission(f *testing.F) {
	f.Add("/api/media_player_proxy/media_player.tv", "Bearer abc", "same-origin", "GET", "")
	f.Add("/api/media_player_proxy/media_player.tv", "Bearer abc", "cross-site", "GET", "")
	f.Add("/api/media_player_proxy/media_player.tv/../camera", "Bearer abc", "same-origin", "GET", "")
	f.Fuzz(func(t *testing.T, path, token, site, method, query string) {
		if len(path)+len(token)+len(site)+len(method)+len(query) > 16384 {
			t.Skip()
		}
		r := &http.Request{Method: method, URL: &url.URL{Path: path, RawQuery: query}, Header: make(http.Header)}
		r.Header.Set("Authorization", token)
		r.Header.Set("Sec-Fetch-Site", site)
		accepted := mediaArtworkRoute(r)
		if accepted {
			if method != "GET" || query != "" || site != "same-origin" || !strings.HasPrefix(path, "/api/media_player_proxy/media_player.") || !strings.HasPrefix(token, "Bearer ") {
				t.Fatal("noncanonical artwork admitted")
			}
			r.Header.Add("Authorization", token)
			if mediaArtworkRoute(r) {
				t.Fatal("duplicate authorization admitted")
			}
			r.Header.Set("Authorization", token)
			r.URL.ForceQuery = true
			if mediaArtworkRoute(r) {
				t.Fatal("empty query marker admitted")
			}
			r.URL.ForceQuery = false
			r.ContentLength = 1
			if mediaArtworkRoute(r) {
				t.Fatal("request body admitted")
			}
		}
	})
}
