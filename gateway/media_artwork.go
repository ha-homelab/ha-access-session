package gateway

import (
	"net/http"
	"regexp"
	"time"
)

const mediaArtworkTimeout = 10 * time.Second

var mediaArtworkPath = regexp.MustCompile(`^/api/media_player_proxy/media_player\.[a-z0-9_]{1,137}$`)
var mediaArtworkBearer = regexp.MustCompile(`^Bearer [A-Za-z0-9._~+/-]+={0,2}$`)

// This is a read-only route to the configured HA upstream, never a URL proxy.
// The common admission checks already verified Host, any supplied Origin and
// the signed Access identity. HA independently validates this bearer token.
func mediaArtworkRoute(r *http.Request) bool {
	if r.Method != http.MethodGet || !mediaArtworkPath.MatchString(r.URL.Path) ||
		r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	authorizations := r.Header.Values("Authorization")
	if len(authorizations) != 1 || len(authorizations[0]) > len("Bearer ")+8192 || !mediaArtworkBearer.MatchString(authorizations[0]) {
		return false
	}
	sites := r.Header.Values("Sec-Fetch-Site")
	if len(sites) > 1 || (len(sites) == 1 && sites[0] != "same-origin") {
		return false
	}
	// Same-origin GET fetches may omit Origin. In that case require the
	// browser's same-origin metadata instead of accepting an ambiguous request.
	return len(r.Header.Values("Origin")) == 1 || len(sites) == 1
}
