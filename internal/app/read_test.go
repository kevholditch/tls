package app

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/kevholditch/tls/internal/app/testutil"
	"github.com/stretchr/testify/assert"
)

func TestCanPrintCert(t *testing.T) {

	server, err := testutil.NewTestServer(func(b *testutil.TlsConfigBuilder) *tls.Config {
		return b.WithCerts(testutil.NewCertBuilder().WithDefault().Build()).
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
	result, err := Read(server.GetAddress())
	if err != nil {
		t.Errorf("failed to read certificate: %v", err)
	}

	assert.Equal(t, "Test Corp", result.Subject.Organization[0])

}
