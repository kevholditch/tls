package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func Read(host string) (*x509.Certificate, error) {
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

	if state.PeerCertificates == nil || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", host)
	}

	return state.PeerCertificates[0], nil
}
