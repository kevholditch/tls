package testutil

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
)

func getRandomPort() (int, error) {

	listener, err := net.Listen("tcp", ":0")

	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, err
	}

	return addr.Port, nil
}

type TestServer struct {
	server *http.Server
}

// NewTestServer creates a new TLS test server
func NewTestServer(buildTlsConfig func(b *TlsConfigBuilder) *tls.Config) (*TestServer, error) {

	port, err := getRandomPort()
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Addr:      fmt.Sprintf("127.0.0.1:%d", port),
		TLSConfig: buildTlsConfig(NewTlsConfigBuilder()),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		}),
	}

	return &TestServer{
		server: server,
	}, nil
}

func (s *TestServer) GetAddress() string {
	return s.server.Addr
}

// Start starts the test server
func (s *TestServer) Start(ready chan<- struct{}) error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Signal that we're ready to accept connections
	ready <- struct{}{}

	// Start serving TLS connections

	if err := s.server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stop stops the test server
func (s *TestServer) Stop() error {
	return s.server.Close()
}
