package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

const sessionBodyTimeout = 2 * time.Second

// stopRequestBody also applies to denials before authentication or body
// validation. net/http may otherwise drain an unfinished body before sending
// the response. An HTTP/2 deadline affects this stream, not other requests.
func stopRequestBody(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
}

// normalizeSessionBody accepts an empty decoded stream, including unknown-length
// HTTP/2 and chunked HTTP/1 requests. Framing alone cannot establish emptiness.
// Call only for an authenticated, allowed session exchange, never an OAuth POST.
func normalizeSessionBody(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	controller := http.NewResponseController(w)
	reject := func(status int) bool {
		// A peer may stop sending after its first rejected byte. Abort any
		// remaining read/drain instead of retaining the connection indefinitely.
		stopRequestBody(w, r)
		http.Error(w, http.StatusText(status), status)
		return false
	}
	if r.ContentLength > 0 || len(r.Trailer) != 0 || len(r.Header.Values("Trailer")) != 0 ||
		len(r.TransferEncoding) > 1 || (len(r.TransferEncoding) == 1 && r.TransferEncoding[0] != "chunked") {
		return reject(http.StatusBadRequest)
	}
	if r.Body != nil && r.Body != http.NoBody {
		deadline := time.Now().Add(sessionBodyTimeout)
		if requestDeadline, ok := ctx.Deadline(); ok && requestDeadline.Before(deadline) {
			deadline = requestDeadline
		}
		// Context cancellation alone does not interrupt a server Body.Read.
		// Fail closed if an embedding ResponseWriter hides deadline support.
		if err := controller.SetReadDeadline(deadline); err != nil {
			return reject(http.StatusInternalServerError)
		}
		var first [1]byte
		n, err := io.ReadFull(r.Body, first[:])
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return reject(http.StatusRequestTimeout)
		}
		if n != 0 || err != io.EOF {
			return reject(http.StatusBadRequest)
		}
		// HTTP/1 trailers can first appear while reading the terminal chunk.
		// Read the original server request before WithContext copies its fields:
		// an initially nil Trailer map is assigned by the server during EOF.
		if len(r.Trailer) != 0 {
			return reject(http.StatusBadRequest)
		}
		if err := r.Body.Close(); err != nil {
			return reject(http.StatusBadRequest)
		}
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			return reject(http.StatusInternalServerError)
		}
	}
	if ctx.Err() != nil {
		return reject(http.StatusRequestTimeout)
	}
	r.Body = http.NoBody
	r.ContentLength = 0
	r.TransferEncoding = nil
	r.Trailer = nil
	r.Header.Del("Content-Length")
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Trailer")
	return true
}
