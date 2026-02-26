package tls

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kevholditch/tls/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func setupExplainTestServer(
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

func localhostTargetFromAddress(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		panic(err)
	}
	return net.JoinHostPort("localhost", port)
}

func TestExplainTrustedChainGradeA(t *testing.T) {
	chainResult, err := testutil.BuildChainForDNSNames("localhost")
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Server", "test-server")
		w.Write([]byte("OK"))
	})

	server := setupExplainTestServer(t, chainResult.ServerCert, []string{"h2", "http/1.1"}, handler)

	roots := x509.NewCertPool()
	roots.AddCert(chainResult.Root)

	result, err := Explain(localhostTargetFromAddress(server.GetAddress()), roots, time.Now())
	assert.NoError(t, err)
	assert.True(t, result.Certificate.ChainTrusted)
	assert.True(t, result.Certificate.HostnameMatch)
	assert.True(t, result.Security.HSTS.Enabled)
	assert.True(t, result.Connection.HTTP2)
	assert.Equal(t, "A", result.Grade.Grade)
}

func TestExplainHostnameMismatchGradeF(t *testing.T) {
	chainResult, err := testutil.BuildChainForDNSNames("localhost")
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Write([]byte("OK"))
	})
	server := setupExplainTestServer(t, chainResult.ServerCert, []string{"h2", "http/1.1"}, handler)

	roots := x509.NewCertPool()
	roots.AddCert(chainResult.Root)

	result, err := Explain(server.GetAddress(), roots, time.Now())
	assert.NoError(t, err)
	assert.False(t, result.Certificate.HostnameMatch)
	assert.Equal(t, "F", result.Grade.Grade)
}

func TestComputeGradeExpiringSoonDowngrades(t *testing.T) {
	result := &ExplainResult{
		Certificate: ExplainCertificate{
			ChainTrusted:  true,
			HostnameMatch: true,
			DaysRemaining: 10,
		},
		TLS: ExplainTLS{
			ServerSelected: "TLS 1.3",
			ForwardSecrecy: true,
		},
		Security: ExplainSecurityFeatures{
			ALPN: ExplainFeature{Available: true, Enabled: true},
			HSTS: ExplainFeature{Available: true, Enabled: true},
		},
		HTTP: ExplainHTTP{
			Available: true,
		},
	}

	grade := computeGrade(result)
	assert.Equal(t, "B", grade.Grade)
	assert.Contains(t, grade.Reasons, "Certificate expires in 30 days or less")
}

func TestComputeGradeHTTPUnavailableDowngrades(t *testing.T) {
	result := &ExplainResult{
		Certificate: ExplainCertificate{
			ChainTrusted:  true,
			HostnameMatch: true,
			DaysRemaining: 60,
		},
		TLS: ExplainTLS{
			ServerSelected: "TLS 1.3",
			ForwardSecrecy: true,
		},
		Security: ExplainSecurityFeatures{
			ALPN: ExplainFeature{Available: true, Enabled: true},
			HSTS: ExplainFeature{Available: false, Enabled: false},
		},
		HTTP: ExplainHTTP{
			Available: false,
		},
	}

	grade := computeGrade(result)
	assert.Equal(t, "B", grade.Grade)
	assert.Contains(t, grade.Reasons, "HTTP probe unavailable")
}
