package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

func TestIssuerRejectsWeakRSAKeysBeforeCaching(t *testing.T) {
	for _, bits := range []int{2048, 2047} {
		signing, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &signing.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
		}))
		for _, strict := range []bool{false, true} {
			transport := http.RoundTripper(http.DefaultTransport)
			if strict {
				transport = keySetTransport{transport}
			}
			ctx := oidc.ClientContext(context.Background(), &http.Client{Transport: transport})
			verifier := oidc.NewVerifier(config().Issuer, oidc.NewRemoteKeySet(ctx, server.URL), &oidc.Config{ClientID: config().Audience, SupportedSigningAlgs: []string{oidc.RS256}})
			_, err = verifier.Verify(ctx, signed(t, signing, claimsMap()))
			if (err == nil) != (bits == 2048 || !strict) {
				t.Errorf("bits=%d strict=%v: %v", bits, strict, err)
			}
		}
		server.Close()
	}
}

func tlsCertificate(t *testing.T, index int, isCA bool, bits int, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(index)), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.DNSNames = []string{"localhost"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent = template
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, der
}

func TestTLSRejectsWeakRootIntermediateAndLeafBeforeHTTP(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, weak := range []int{-1, 0, 1, 2} {
			bits := []int{2048, 2048, 2048}
			if weak >= 0 {
				bits[weak] = 2047
			}
			root, rootKey, _ := tlsCertificate(t, 1, true, bits[0], nil, nil)
			intermediate, intermediateKey, intermediateDER := tlsCertificate(t, 2, true, bits[1], root, rootKey)
			_, leafKey, leafDER := tlsCertificate(t, 3, false, bits[2], intermediate, intermediateKey)
			var hits atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, intermediateDER}, PrivateKey: leafKey}}}
			server.StartTLS()
			roots := x509.NewCertPool()
			roots.AddCert(root)
			for _, strict := range []bool{false, true} {
				transport := secureTransport()
				transport.TLSClientConfig.RootCAs = roots
				transport.TLSClientConfig.ServerName = "localhost"
				if !strict {
					transport.TLSClientConfig.VerifyConnection = nil
				}
				before := hits.Load()
				response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(server.URL)
				if response != nil {
					response.Body.Close()
				}
				transport.CloseIdleConnections()
				want := !strict || weak < 0
				if (err == nil) != want || (hits.Load() > before) != want {
					t.Errorf("TLS=%x weak=%d strict=%v err=%v hits=%d", version, weak, strict, err, hits.Load()-before)
				}
			}
			server.Close()
		}
	}
}

func TestHTTPSListenerRejectsWeakConfiguredChain(t *testing.T) {
	for _, weak := range []int{-1, 0, 1, 2} {
		bits := []int{2048, 2048, 2048}
		if weak >= 0 {
			bits[weak] = 2047
		}
		root, rootKey, rootDER := tlsCertificate(t, 1, true, bits[0], nil, nil)
		intermediate, intermediateKey, intermediateDER := tlsCertificate(t, 2, true, bits[1], root, rootKey)
		_, leafKey, leafDER := tlsCertificate(t, 3, false, bits[2], intermediate, intermediateKey)
		directory := t.TempDir()
		certificatePath := filepath.Join(directory, "certificate.pem")
		keyPath := filepath.Join(directory, "key.pem")
		var certificates []byte
		for _, der := range [][]byte{leafDER, intermediateDER, rootDER} {
			certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		if err := os.WriteFile(certificatePath, certificates, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}), 0600); err != nil {
			t.Fatal(err)
		}
		config, err := ServerTLSConfig(certificatePath, keyPath)
		if (err == nil) != (weak < 0) {
			t.Fatalf("weak=%d error=%v", weak, err)
		}
		if config != nil && (config.MinVersion < tls.VersionTLS12 || len(config.Certificates) != 1) {
			t.Fatal("incomplete HTTPS listener policy")
		}
	}
}
