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

func TestReadCommandWithCertExpiringInLessThanOneWeek(t *testing.T) {

	exampleCert := testutil.NewCertBuilder().WithSubject(func() pkix.Name {
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
		WithNotAfter(time.Now().Add(day)).
		WithKeyUsage(x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature).
		WithExtKeyUsage(x509.ExtKeyUsageServerAuth).
		WithSerialNumber(big.NewInt(123)).
		BuildCert()

	server, err := testutil.NewTestServer(func(b *testutil.TlsConfigBuilder) *tls.Config {
		return b.WithCerts(testutil.NewCertBuilder().WithCert(exampleCert).Build()).
			WithMaximumTLSVersion(tls.VersionTLS13).
			WithMinimumTLSVersion(tls.VersionTLS12).
			Build()
	})

	if err != nil {
		t.Fatal(err)
	}

	// Create a channel to signal when the server is ready
	ready := make(chan struct{})

	go func() {
		if err := server.Start(ready); err != nil {
			t.Errorf("Test server error: %v", err)
		}
	}()

	// Wait for server to be ready
	select {
	case <-ready:
		// Server is ready
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for server to start")
	}

	// Ensure the server is stopped when the test ends
	defer func(server *testutil.TestServer) {
		err := server.Stop()
		if err != nil {
			t.Errorf("failed to stop server: %v", err)
		}
	}(server)

	// Your test code here...
	var in, out, errOut bytes.Buffer
	app := NewApp(&in, &out, &errOut)

	err = app.Run("read", server.GetAddress())
	if err != nil {
		t.Errorf("failed to read certificate: %v", err)
	}

	fmt.Println(out.String())
	assert.Contains(t, out.String(), "Common Name:  example.com")
	assert.Contains(t, out.String(), "Subject:      CN=example.com,O=Test Corp")
	assert.Contains(t, out.String(), "DNS Names:    []")
	assert.Contains(t, out.String(), fmt.Sprintf("Not Before:   %s", exampleCert.NotBefore.Format(time.RFC3339)))
	assert.Contains(t, out.String(), fmt.Sprintf("Not After:    %s", exampleCert.NotAfter.Format(time.RFC3339)))
	assert.Contains(t, out.String(), fmt.Sprintf("Expires In:   ⚠️ 23 Hours 0 Days"))
	assert.Contains(t, out.String(), "Issuer:       CN=example.com,O=Test Corp")
	assert.Contains(t, out.String(), "Serial:       123")

}

func TestReadCommandWithCertExpiringInMoreThanOneWeek(t *testing.T) {

	exampleCert := testutil.NewCertBuilder().WithSubject(func() pkix.Name {
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
		WithSerialNumber(big.NewInt(123)).
		BuildCert()

	server, err := testutil.NewTestServer(func(b *testutil.TlsConfigBuilder) *tls.Config {
		return b.WithCerts(testutil.NewCertBuilder().WithCert(exampleCert).Build()).
			WithMaximumTLSVersion(tls.VersionTLS13).
			WithMinimumTLSVersion(tls.VersionTLS12).
			Build()
	})

	if err != nil {
		t.Fatal(err)
	}

	// Create a channel to signal when the server is ready
	ready := make(chan struct{})

	go func() {
		if err := server.Start(ready); err != nil {
			t.Errorf("Test server error: %v", err)
		}
	}()

	// Wait for server to be ready
	select {
	case <-ready:
		// Server is ready
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for server to start")
	}

	// Ensure the server is stopped when the test ends
	defer func(server *testutil.TestServer) {
		err := server.Stop()
		if err != nil {
			t.Errorf("failed to stop server: %v", err)
		}
	}(server)

	// Your test code here...
	var in, out, errOut bytes.Buffer
	app := NewApp(&in, &out, &errOut)

	err = app.Run("read", server.GetAddress())
	if err != nil {
		t.Errorf("failed to read certificate: %v", err)
	}

	fmt.Println(out.String())
	assert.Contains(t, out.String(), "Common Name:  example.com")
	assert.Contains(t, out.String(), "Subject:      CN=example.com,O=Test Corp")
	assert.Contains(t, out.String(), "DNS Names:    []")
	assert.Contains(t, out.String(), fmt.Sprintf("Not Before:   %s", exampleCert.NotBefore.Format(time.RFC3339)))
	assert.Contains(t, out.String(), fmt.Sprintf("Not After:    %s", exampleCert.NotAfter.Format(time.RFC3339)))
	assert.Contains(t, out.String(), fmt.Sprintf("Expires In:   ✅ 23 Hours 9 Days"))
	assert.Contains(t, out.String(), "Issuer:       CN=example.com,O=Test Corp")
	assert.Contains(t, out.String(), "Serial:       123")

}
