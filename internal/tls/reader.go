package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

func Read(host string, mode Mode, roots *x509.CertPool) (*ReadResult, error) {
	if mode == ModeAuto {
		mode = DetectMode(host)
	}

	if mode == ModeFile {
		return ReadFile(host, roots)
	}

	addr, err := GetAddress(host, defaultPort)
	if err != nil {
		return nil, err
	}

	return ReadServer(addr, roots)
}

func ReadServer(host string, roots *x509.CertPool) (*ReadResult, error) {
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	state := conn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", host)
	}

	chain := state.PeerCertificates
	verifiedChains := verifyChain(chain, roots, time.Now())

	return &ReadResult{
		Chain:          chain,
		VerifiedChains: verifiedChains,
	}, nil
}

func ReadFile(path string, roots *x509.CertPool) (*ReadResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var chain []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}

	verifiedChains := verifyChain(chain, roots, time.Now())

	return &ReadResult{
		Chain:          chain,
		VerifiedChains: verifiedChains,
	}, nil
}
