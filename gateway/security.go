package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// Certificate verification runs first; every certificate in an accepted chain
// must also meet the public-key floor, including intermediates and the root.
func publicKeyMeetsMinimum(public any) bool {
	switch key := public.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize >= 224
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}

func strongVerifiedChain(state tls.ConnectionState) error {
	for _, chain := range state.VerifiedChains {
		strong := len(chain) > 0
		for _, certificate := range chain {
			strong = strong && publicKeyMeetsMinimum(certificate.PublicKey)
		}
		if strong {
			return nil
		}
	}
	return errors.New("no verified certificate chain meets the public-key policy")
}

// ServerTLSConfig validates every configured certificate before a listener opens.
// Normal clients still verify the certificate chain and hostname independently.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	for _, der := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if !publicKeyMeetsMinimum(parsed.PublicKey) {
			return nil, errors.New("server certificate is below the public-key minimum")
		}
	}
	config := secureTransport().TLSClientConfig.Clone()
	config.Certificates = []tls.Certificate{certificate}
	config.VerifyConnection = nil
	return config, nil
}

func secureTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Administrative endpoints are explicit; ambient proxies must not receive tokens.
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		VerifyConnection: strongVerifiedChain,
	}
	return transport
}

type keySetTransport struct{ inner http.RoundTripper }

// Filter before go-oidc caches any key: selecting RS256 alone does not impose
// an RSA modulus floor. The same 2048-bit floor is used by the HA verifier.
func (transport keySetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.inner.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(body) > 65536 {
		return nil, errors.New("issuer key set exceeds size limit")
	}
	if response.StatusCode == http.StatusOK {
		var keys jose.JSONWebKeySet
		if err = json.Unmarshal(body, &keys); err != nil {
			return nil, errors.New("invalid issuer key set")
		}
		allowed := make([]jose.JSONWebKey, 0, len(keys.Keys))
		for _, key := range keys.Keys {
			public, ok := key.Key.(*rsa.PublicKey)
			if ok && public.N.BitLen() >= 2048 && key.Algorithm == "RS256" && key.Use == "sig" && len(key.KeyID) > 0 && len(key.KeyID) <= 256 {
				allowed = append(allowed, key)
			}
		}
		if len(allowed) == 0 {
			return nil, errors.New("issuer has no supported signing key")
		}
		body, err = json.Marshal(jose.JSONWebKeySet{Keys: allowed})
		if err != nil {
			return nil, err
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Del("Content-Length")
	return response, nil
}
