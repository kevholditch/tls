package app

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const defaultPort = 443

type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeFile   Mode = "file"
	ModeServer Mode = "server"
)

func ParseMode(s string) (Mode, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mode := Mode(s)
	switch mode {
	case ModeAuto, ModeFile, ModeServer:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid mode: %s (must be auto, file, or server)", s)
	}
}

func Read(host string, mode Mode) (*x509.Certificate, error) {

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

func ReadServer(host string) (*x509.Certificate, error) {
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

	return state.PeerCertificates[0], nil
}

func ReadFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
