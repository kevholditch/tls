package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kevholditch/tls/internal/pretty"
	"github.com/kevholditch/tls/internal/testutil"
	tlspkg "github.com/kevholditch/tls/internal/tls"
	"github.com/stretchr/testify/assert"
)

var day = 24 * time.Hour
var tenDays = 10 * day

func DefaultCertBuilder() *testutil.CertBuilder {
	return testutil.NewCertBuilder().WithSubject(func() pkix.Name {
		return pkix.Name{
			Organization: []string{"Test Corp"},
			CommonName:   "example.com",
		}
	}).WithIssuer(func() pkix.Name {
		return pkix.Name{
			CommonName: "Root CA Inc",
			Organization: []string{
				"Root CA Inc",
			},
		}
	}).WithNotBefore(time.Now()).
		WithNotAfter(time.Now().Add(tenDays)).
		WithKeyUsage(x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature).
		WithExtKeyUsage(x509.ExtKeyUsageServerAuth).
		WithSerialNumber(big.NewInt(123))
}

// buildExampleCertThatExpiresIn creates a test certificate with the given validity duration
func buildExampleCertThatExpiresIn(validityDuration time.Duration) *x509.Certificate {
	return DefaultCertBuilder().WithValidityDuration(validityDuration).BuildCert()
}

func buildExampleCertWithDNSNames(dnsNames ...string) *x509.Certificate {
	return DefaultCertBuilder().WithDNSNames(dnsNames...).BuildCert()
}

func writePEMFile(t *testing.T, cert *x509.Certificate) string {
	certPath := path.Join(os.TempDir(), fmt.Sprintf("cert-%s.pem", uuid.New().String()))

	// Create a properly signed certificate to get Raw bytes
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	derBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)
	assert.NoError(t, err)

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	err = os.WriteFile(certPath, pem.EncodeToMemory(pemBlock), 0644)
	assert.NoError(t, err)

	return certPath
}

// writePEMFileChain writes a PEM file with the given certs in order (leaf first, then intermediates, then root).
func writePEMFileChain(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	certPath := path.Join(os.TempDir(), fmt.Sprintf("cert-chain-%s.pem", uuid.New().String()))
	var data []byte
	for _, cert := range certs {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	err := os.WriteFile(certPath, data, 0644)
	assert.NoError(t, err)
	return certPath
}

// setupTestServer creates and starts a test server with the given certificate
func setupTestServer(t *testing.T, cert *x509.Certificate) *testutil.TestServer {
	t.Helper()

	server, err := testutil.NewTestServer(func(b *testutil.TlsConfigBuilder) *tls.Config {
		return b.WithCerts(testutil.NewCertBuilder().WithCert(cert).Build()).
			WithMaximumTLSVersion(tls.VersionTLS13).
			WithMinimumTLSVersion(tls.VersionTLS12).
			Build()
	})
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	ready := make(chan struct{})
	go func() {
		if err := server.Start(ready); err != nil {
			t.Errorf("test server error: %v", err)
		}
	}()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("failed to stop server: %v", err)
		}
	})

	return server
}

// setupTestServerWithCert creates and starts a test server with the given tls.Certificate (e.g. a chain).
func setupTestServerWithCert(t *testing.T, serverCert tls.Certificate) *testutil.TestServer {
	t.Helper()
	server, err := testutil.NewTestServer(func(b *testutil.TlsConfigBuilder) *tls.Config {
		return b.WithCerts(serverCert).
			WithMaximumTLSVersion(tls.VersionTLS13).
			WithMinimumTLSVersion(tls.VersionTLS12).
			Build()
	})
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	ready := make(chan struct{})
	go func() {
		if err := server.Start(ready); err != nil {
			t.Errorf("test server error: %v", err)
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}
	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("failed to stop server: %v", err)
		}
	})
	return server
}

// runReadCommand runs the read command and returns the output
func runReadCommand(t *testing.T, readArgs ...string) string {
	t.Helper()

	var out, errOut bytes.Buffer

	args := append([]string{"read"}, readArgs...)
	err := Run(&out, &errOut, args)
	if err != nil {
		t.Fatalf("failed to read certificate: %v", err)
	}

	return out.String()
}

func TestReadCommandServerWithCertExpiringInLessThanOneWeek(t *testing.T) {
	exampleCert := buildExampleCertThatExpiresIn(day)
	server := setupTestServer(t, exampleCert)
	output := runReadCommand(t, server.GetAddress())

	assert.Contains(t, output, "Common Name:  example.com")
	assert.Contains(t, output, "Subject:      CN=example.com,O=Test Corp")
	assert.Contains(t, output, fmt.Sprintf("Not Before:   %s", exampleCert.NotBefore.Format(time.RFC3339)))
	assert.Contains(t, output, fmt.Sprintf("Not After:    %s", exampleCert.NotAfter.Format(time.RFC3339)))
	assert.Contains(t, output, "Issuer:       CN=example.com,O=Test Corp")
	assert.Contains(t, output, "Serial:       123")
	assert.Contains(t, output, "Expires In:   ⚠️ 23 Hours")
	assert.Contains(t, output, "DNS Names:    []")
	assert.Contains(t, output, "Trust chain")
	assert.Contains(t, output, "✗ example.com")
}

func TestReadCommandServerWithCertExpiringInMoreThanOneWeek(t *testing.T) {
	exampleCert := buildExampleCertThatExpiresIn(tenDays)
	server := setupTestServer(t, exampleCert)
	output := runReadCommand(t, server.GetAddress())

	assert.Contains(t, output, "Common Name:  example.com")
	assert.Contains(t, output, "Subject:      CN=example.com,O=Test Corp")
	assert.Contains(t, output, fmt.Sprintf("Not Before:   %s", exampleCert.NotBefore.Format(time.RFC3339)))
	assert.Contains(t, output, fmt.Sprintf("Not After:    %s", exampleCert.NotAfter.Format(time.RFC3339)))
	assert.Contains(t, output, "Issuer:       CN=example.com,O=Test Corp")
	assert.Contains(t, output, "Serial:       123")
	assert.Contains(t, output, "Expires In:   ✅ 9 Days 23 Hours")
	assert.Contains(t, output, "DNS Names:    []")
	assert.Contains(t, output, "Trust chain")
	assert.Contains(t, output, "✗ example.com")
}

func TestReadCommandServerWithCertWithManyAlternativeNames(t *testing.T) {
	exampleCert := buildExampleCertWithDNSNames("api.example.com", "web.example.com", "www.example.com")
	server := setupTestServer(t, exampleCert)
	output := runReadCommand(t, server.GetAddress())

	assert.Contains(t, output, "Common Name:  example.com")
	assert.Contains(t, output, "Subject:      CN=example.com,O=Test Corp")
	assert.Contains(t, output, fmt.Sprintf("Not Before:   %s", exampleCert.NotBefore.Format(time.RFC3339)))
	assert.Contains(t, output, fmt.Sprintf("Not After:    %s", exampleCert.NotAfter.Format(time.RFC3339)))
	assert.Contains(t, output, "Issuer:       CN=example.com,O=Test Corp")
	assert.Contains(t, output, "Serial:       123")
	assert.Contains(t, output, "Expires In:   ✅ 9 Days 23 Hours")
	assert.Contains(t, output, `DNS Names:    [
                api.example.com,
                web.example.com,
                www.example.com
              ]`)
	assert.Contains(t, output, "Trust chain")
	assert.Contains(t, output, "✗ example.com")
}

func TestReadCommandPEMFileTrustedChain(t *testing.T) {
	chainResult, err := testutil.BuildChain()
	assert.NoError(t, err)
	filePath := writePEMFileChain(t, chainResult.Leaf, chainResult.Intermediate, chainResult.Root)

	pool := x509.NewCertPool()
	pool.AddCert(chainResult.Root)

	result, err := tlspkg.Read(filePath, tlspkg.ModeFile, pool)
	assert.NoError(t, err)

	var buf bytes.Buffer
	err = pretty.Print(&buf, result, time.Now())
	assert.NoError(t, err)
	output := buf.String()

	assert.Contains(t, output, "Trust chain")
	assert.Contains(t, output, "✓ example.com")
	assert.Contains(t, output, "✓ Test Intermediate CA")
	assert.Contains(t, output, "✓ Test Root CA")
}

func TestReadCommandServerTrustedChain(t *testing.T) {
	chainResult, err := testutil.BuildChain()
	assert.NoError(t, err)
	server := setupTestServerWithCert(t, chainResult.ServerCert)

	pool := x509.NewCertPool()
	pool.AddCert(chainResult.Root)

	result, err := tlspkg.Read(server.GetAddress(), tlspkg.ModeServer, pool)
	assert.NoError(t, err)

	var buf bytes.Buffer
	err = pretty.Print(&buf, result, time.Now())
	assert.NoError(t, err)
	output := buf.String()

	assert.Contains(t, output, "Trust chain")
	assert.Contains(t, output, "✓ example.com")
	assert.Contains(t, output, "✓ Test Intermediate CA")
}

func TestReadCommandPEMFile(t *testing.T) {
	exampleCert := buildExampleCertWithDNSNames("api.example.com", "web.example.com", "www.example.com")
	filePath := writePEMFile(t, exampleCert)
	output := runReadCommand(t, filePath)

	assert.Contains(t, output, "Common Name:  example.com")
	assert.Contains(t, output, "Subject:      CN=example.com,O=Test Corp")
	assert.Contains(t, output, fmt.Sprintf("Not Before:   %s", exampleCert.NotBefore.Format(time.RFC3339)))
	assert.Contains(t, output, fmt.Sprintf("Not After:    %s", exampleCert.NotAfter.Format(time.RFC3339)))
	assert.Contains(t, output, "Issuer:       CN=example.com,O=Test Corp")
	assert.Contains(t, output, "Serial:       123")
	assert.Contains(t, output, "Expires In:   ✅ 9 Days 23 Hours")
	assert.Contains(t, output, `DNS Names:    [
                api.example.com,
                web.example.com,
                www.example.com
              ]`)
	assert.Contains(t, output, "Trust chain")
	assert.Contains(t, output, "✗ example.com")
}
