package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kevholditch/tls/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func runExplainCommand(t *testing.T, explainArgs ...string) string {
	t.Helper()

	var out, errOut bytes.Buffer
	args := append([]string{"explain"}, explainArgs...)
	err := Run(&out, &errOut, args)
	if err != nil {
		t.Fatalf("failed to explain tls connection: %v", err)
	}

	return out.String()
}

func setupExplainServerWithCert(
	t *testing.T,
	serverCert tls.Certificate,
	nextProtos []string,
	handler http.Handler,
) *testutil.TestServer {
	t.Helper()

	server, err := testutil.NewTestServerWithOptions(func(b *testutil.TlsConfigBuilder) *tls.Config {
		return b.WithCerts(serverCert).
			WithMinimumTLSVersion(tls.VersionTLS12).
			WithMaximumTLSVersion(tls.VersionTLS13).
			WithNextProtos(nextProtos...).
			Build()
	}, &testutil.TestServerOptions{
		Handler: handler,
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

func localhostTarget(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		panic(err)
	}
	return net.JoinHostPort("localhost", port)
}

func TestExplainCommandServerOutputSections(t *testing.T) {
	cert := DefaultCertBuilder().
		WithSubject(func() pkix.Name {
			return pkix.Name{
				Organization: []string{"Test Corp"},
				CommonName:   "localhost",
			}
		}).
		WithDNSNames("localhost").
		Build()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Server", "test-server")
		w.Write([]byte("OK"))
	})

	server := setupExplainServerWithCert(t, cert, []string{"h2", "http/1.1"}, handler)
	output := runExplainCommand(t, localhostTarget(server.GetAddress()))

	assert.Contains(t, output, "TLS CONNECTION EXPLANATION")
	assert.Contains(t, output, "DNS")
	assert.Contains(t, output, "TLS NEGOTIATION")
	assert.Contains(t, output, "CERTIFICATE")
	assert.Contains(t, output, "SECURITY FEATURES")
	assert.Contains(t, output, "HTTP LAYER")
	assert.Contains(t, output, "OVERALL SECURITY RATING")
	assert.Contains(t, output, "OCSP Stapling:")
	assert.Contains(t, output, "Absent ❌")
	assert.Contains(t, output, "Chain validation failed against system trust store")
}

func TestExplainCommandURLInput(t *testing.T) {
	cert := DefaultCertBuilder().
		WithSubject(func() pkix.Name {
			return pkix.Name{
				Organization: []string{"Test Corp"},
				CommonName:   "localhost",
			}
		}).
		WithDNSNames("localhost").
		Build()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Write([]byte("OK"))
	})

	server := setupExplainServerWithCert(t, cert, []string{"h2", "http/1.1"}, handler)
	_, port, err := net.SplitHostPort(server.GetAddress())
	assert.NoError(t, err)

	target := fmt.Sprintf("https://localhost:%s", port)
	output := runExplainCommand(t, target)

	assert.Contains(t, output, "Target:")
	assert.Contains(t, output, "localhost")
	assert.Contains(t, output, "Port:")
	assert.Contains(t, output, fmt.Sprintf(" %s\n", port))
}

func TestExplainCommandRejectsFileInput(t *testing.T) {
	exampleCert := buildExampleCertWithDNSNames("localhost")
	filePath := writePEMFile(t, exampleCert)

	var out, errOut bytes.Buffer
	err := Run(&out, &errOut, []string{"explain", filePath})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "explain only supports server targets")
	assert.Contains(t, err.Error(), "tls read <file>")
}
