package app

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/kevholditch/tls/internal/app/testutil"
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

// runReadCommand runs the read command and returns the output
func runReadCommand(t *testing.T, server *testutil.TestServer) string {
	t.Helper()

	var in, out, errOut bytes.Buffer
	app := NewApp(&in, &out, &errOut)

	err := app.Run("read", server.GetAddress())
	if err != nil {
		t.Fatalf("failed to read certificate: %v", err)
	}

	return out.String()
}

// assertCommonFields asserts the common certificate fields that appear in both tests
func assertCommonFields(t *testing.T, output string, cert *x509.Certificate) {
	t.Helper()

	assert.Contains(t, output, "Common Name:  example.com")
	assert.Contains(t, output, "Subject:      CN=example.com,O=Test Corp")
	assert.Contains(t, output, fmt.Sprintf("Not Before:   %s", cert.NotBefore.Format(time.RFC3339)))
	assert.Contains(t, output, fmt.Sprintf("Not After:    %s", cert.NotAfter.Format(time.RFC3339)))
	assert.Contains(t, output, "Issuer:       CN=example.com,O=Test Corp")
	assert.Contains(t, output, "Serial:       123")
}

func TestReadCommandWithCertExpiringInLessThanOneWeek(t *testing.T) {
	exampleCert := buildExampleCertThatExpiresIn(day)
	server := setupTestServer(t, exampleCert)
	output := runReadCommand(t, server)

	fmt.Println(output)
	assertCommonFields(t, output, exampleCert)
	assert.Contains(t, output, "Expires In:   ⚠️ 23 Hours")
	assert.Contains(t, output, "DNS Names:    []")
}

func TestReadCommandWithCertExpiringInMoreThanOneWeek(t *testing.T) {
	exampleCert := buildExampleCertThatExpiresIn(tenDays)
	server := setupTestServer(t, exampleCert)
	output := runReadCommand(t, server)

	fmt.Println(output)
	assertCommonFields(t, output, exampleCert)
	assert.Contains(t, output, "Expires In:   ✅ 9 Days 23 Hours")
	assert.Contains(t, output, "DNS Names:    []")
}

func TestReadCommandWithCertWithManyAlternativeNames(t *testing.T) {
	exampleCert := buildExampleCertWithDNSNames("api.example.com", "web.example.com", "www.example.com")
	server := setupTestServer(t, exampleCert)
	output := runReadCommand(t, server)

	fmt.Println(output)
	assertCommonFields(t, output, exampleCert)
	assert.Contains(t, output, "Expires In:   ✅ 9 Days 23 Hours")
	assert.Contains(t, output, `DNS Names:    [
                api.example.com,
                web.example.com,
                www.example.com
              ]`)
}
