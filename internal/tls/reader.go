package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func Read(host string, mode Mode) ([]*x509.Certificate, error) {

	if mode == ModeAuto {
		mode = DetectMode(host)
	}

	if mode == ModeFile {
		return ReadFile(host)
	}

	addr, err := GetAddress(host, defaultPort)
	if err != nil {
		return nil, err

	}

	return ReadServer(addr)
}

func ReadServer(host string) ([]*x509.Certificate, error) {
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

	return state.PeerCertificates, nil
}

func ReadFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return certs, nil
}
