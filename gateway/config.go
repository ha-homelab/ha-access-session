// Package gateway implements the version 1 HA Access Session boundary.
package gateway

import (
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const AssertionHeader = "Cf-Access-Jwt-Assertion"
const SessionPath = "/api/ha_access_session/v1/session"
const ContractVersion = 1

// Config is trusted administrator input. No request can override these values.
type Config struct {
	Issuer                string `json:"issuer"`
	Origin                string `json:"origin"`
	Audience              string `json:"audience"`
	Email                 string `json:"email"`
	Upstream              string `json:"upstream"`
	AllowInsecureUpstream bool   `json:"allow_insecure_upstream"`
	AllowTrustedNetwork   bool   `json:"allow_trusted_network"`
	StaticDir             string `json:"static_dir"`
	// Default-off compatibility with the normal HA OAuth login UI.
	EnableHALogin bool `json:"enable_ha_login"`
	// Default-off authenticated reads of canonical HA media-player artwork.
	EnableMediaArtwork bool `json:"enable_media_artwork"`
	// Trusted embed.FS adapter input, never configurable by an HTTP request.
	StaticFS              fs.FS  `json:"-"`
	ContentSecurityPolicy string `json:"content_security_policy"`
	// Optional compatibility adapter route. Never selected from a request.
	SessionPath                 string `json:"session_path"`
	MaxAssertionLifetimeSeconds int    `json:"max_assertion_lifetime_seconds"`
	MaxConnectionSeconds        int    `json:"max_connection_seconds"`
}

func origin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery ||
		strings.ContainsAny(raw, " \t\r\n\\") {
		return nil, fmt.Errorf("expected an HTTPS origin without a trailing slash")
	}
	return u, nil
}

func (c *Config) normalize() error {
	if _, err := origin(c.Issuer); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if _, err := origin(c.Origin); err != nil {
		return fmt.Errorf("origin: %w", err)
	}
	if len(c.Audience) == 0 || len(c.Audience) > 256 || strings.ContainsAny(c.Audience, " \t\r\n") {
		return fmt.Errorf("invalid audience")
	}
	if strings.Count(c.Email, "@") != 1 || strings.HasPrefix(c.Email, "@") || strings.HasSuffix(c.Email, "@") ||
		len(c.Email) > 254 || strings.ContainsAny(c.Email, " \t\r\n") {
		return fmt.Errorf("invalid mapped email")
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" ||
		u.Fragment != "" || u.ForceQuery || (u.Scheme != "https" && !(u.Scheme == "http" && c.AllowInsecureUpstream)) {
		return fmt.Errorf("upstream must be an HTTPS origin; HTTP requires allow_insecure_upstream")
	}
	if c.StaticFS != nil && c.StaticDir != "" {
		return fmt.Errorf("choose static_dir or StaticFS")
	}
	if strings.ContainsAny(c.ContentSecurityPolicy, "\r\n") {
		return fmt.Errorf("invalid content security policy")
	}
	if c.SessionPath == "" {
		c.SessionPath = SessionPath
	}
	if !regexp.MustCompile(`^/api/[a-zA-Z0-9_/-]+$`).MatchString(c.SessionPath) ||
		strings.Contains(c.SessionPath, "//") {
		return fmt.Errorf("invalid session_path")
	}
	if c.MaxAssertionLifetimeSeconds == 0 {
		c.MaxAssertionLifetimeSeconds = 86400
	}
	if c.MaxAssertionLifetimeSeconds < 1 || c.MaxAssertionLifetimeSeconds > 86400 {
		return fmt.Errorf("invalid assertion lifetime")
	}
	if c.MaxConnectionSeconds == 0 {
		c.MaxConnectionSeconds = 300
	}
	if c.MaxConnectionSeconds < 1 || c.MaxConnectionSeconds > 300 {
		return fmt.Errorf("invalid connection lifetime")
	}
	return nil
}

func (c Config) connectionLifetime() time.Duration {
	return time.Duration(c.MaxConnectionSeconds) * time.Second
}
