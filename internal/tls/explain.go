package tls

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cryptotls "crypto/tls"
)

const (
	connectTimeout = 5 * time.Second
	httpTimeout    = 3 * time.Second
)

func Explain(target string, roots *x509.CertPool, now time.Time) (*ExplainResult, error) {
	parsed, err := parseExplainTarget(target)
	if err != nil {
		return nil, err
	}

	result := &ExplainResult{
		Target: ExplainTarget{
			Original: target,
			Host:     parsed.host,
			Port:     parsed.port,
			Address:  parsed.address,
			Protocol: "HTTPS",
		},
		TLS: ExplainTLS{
			ClientOffered: []string{"TLS 1.2", "TLS 1.3"},
		},
	}

	resolveDNS(result)

	state, chain, verifiedChains, tcpDuration, err := establishTLSConnection(parsed.address, parsed.host, roots, now)
	if err != nil {
		return nil, err
	}

	result.Connection.TCPConnected = true
	result.Connection.TCPDuration = tcpDuration
	result.Connection.ALPNProtocol = state.NegotiatedProtocol
	result.Connection.HTTP2 = state.NegotiatedProtocol == "h2"

	result.TLS.ServerSelected = tlsVersionName(state.Version)
	result.TLS.CipherSuite = cryptotls.CipherSuiteName(state.CipherSuite)
	result.TLS.ForwardSecrecy = hasForwardSecrecy(state.Version, state.CipherSuite)
	result.TLS.ForwardSecrecyInfo = forwardSecrecyInfo(state.Version, state.CipherSuite)
	result.TLS.KeyExchangeMethod = keyExchangeMethod(state.Version, state.CipherSuite, result.TLS.ForwardSecrecy)
	result.TLS.KeyExchangeCurve = curveName(state.CurveID)
	result.TLS.OCSPStapling = len(state.OCSPResponse) > 0
	result.TLS.SecureRenegotiation = state.Version >= cryptotls.VersionTLS12

	leaf := chain[0]
	hostnameErr := leaf.VerifyHostname(parsed.host)
	hostnameMatch := hostnameErr == nil

	result.Certificate = ExplainCertificate{
		Leaf:           leaf,
		Chain:          chain,
		VerifiedChains: verifiedChains,
		Hostname:       parsed.host,
		HostnameMatch:  hostnameMatch,
		ChainTrusted:   len(verifiedChains) > 0,
		ExpiresIn:      leaf.NotAfter.Sub(now),
		Expired:        now.After(leaf.NotAfter),
		NotYetValid:    now.Before(leaf.NotBefore),
	}
	if hostnameErr != nil {
		result.Certificate.HostnameError = hostnameErr.Error()
	}
	result.Certificate.DaysRemaining = int(result.Certificate.ExpiresIn.Hours() / 24)

	result.HTTP = probeHTTP(parsed.host, parsed.port)
	result.Security = buildSecurityFeatures(result)
	result.Grade = computeGrade(result)

	return result, nil
}

type explainTarget struct {
	host    string
	port    int
	address string
}

func parseExplainTarget(target string) (*explainTarget, error) {
	if target == "" {
		return nil, ErrNoHostProvided
	}

	if target == "-" || DetectMode(target) == ModeFile {
		return nil, fmt.Errorf("explain only supports server targets; use `tls read <file>` for certificates")
	}

	var host string
	var port int
	if strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://") {
		u, err := url.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		host = u.Hostname()
		if host == "" {
			return nil, ErrNoHostProvided
		}
		if p := u.Port(); p != "" {
			parsedPort, err := strconv.Atoi(p)
			if err != nil {
				return nil, NewErrInvalidHost(target)
			}
			port = parsedPort
		}
	}

	if host == "" {
		addr, err := GetAddress(target, defaultPort)
		if err != nil {
			return nil, err
		}
		parsedHost, parsedPort, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, NewErrInvalidHost(target)
		}
		host = parsedHost
		port, err = strconv.Atoi(parsedPort)
		if err != nil {
			return nil, NewErrInvalidHost(target)
		}
	}

	if port == 0 {
		port = defaultPort
	}

	return &explainTarget{
		host:    host,
		port:    port,
		address: net.JoinHostPort(host, strconv.Itoa(port)),
	}, nil
}

func resolveDNS(result *ExplainResult) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, result.Target.Host)
	if err != nil {
		result.DNS.Error = err.Error()
		return
	}
	if len(ips) == 0 {
		result.DNS.Error = "no IP addresses returned"
		return
	}

	selected := chooseIP(ips)
	result.DNS.Resolved = true
	result.DNS.IP = selected
	result.Target.IP = selected
}

func chooseIP(ips []net.IPAddr) string {
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return ip.IP.String()
		}
	}
	return ips[0].IP.String()
}

func establishTLSConnection(address, host string, roots *x509.CertPool, now time.Time) (cryptotls.ConnectionState, []*x509.Certificate, [][]*x509.Certificate, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: connectTimeout}
	start := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return cryptotls.ConnectionState{}, nil, nil, 0, err
	}
	tcpDuration := time.Since(start)

	tlsConn := cryptotls.Client(rawConn, &cryptotls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         cryptotls.VersionTLS12,
		MaxVersion:         cryptotls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	defer func() {
		_ = tlsConn.Close()
	}()

	if err := tlsConn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		return cryptotls.ConnectionState{}, nil, nil, 0, err
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return cryptotls.ConnectionState{}, nil, nil, 0, err
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return cryptotls.ConnectionState{}, nil, nil, 0, err
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return cryptotls.ConnectionState{}, nil, nil, 0, fmt.Errorf("no certificates found for %s", address)
	}

	chain := state.PeerCertificates
	verifiedChains := verifyChain(chain, roots, now)
	return state, chain, verifiedChains, tcpDuration, nil
}

func probeHTTP(host string, port int) ExplainHTTP {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	reqURL := fmt.Sprintf("https://%s", address)

	transport := &http.Transport{
		TLSClientConfig: &cryptotls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         cryptotls.VersionTLS12,
			MaxVersion:         cryptotls.VersionTLS13,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
	}

	resp, err := client.Get(reqURL)
	if err != nil {
		return ExplainHTTP{
			Available: false,
			Error:     err.Error(),
		}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	compression := "Disabled"
	if resp.Header.Get("Content-Encoding") != "" {
		compression = "Enabled"
	}

	return ExplainHTTP{
		Available:   true,
		Protocol:    resp.Proto,
		Compression: compression,
		Server:      resp.Header.Get("Server"),
		HSTSHeader:  resp.Header.Get("Strict-Transport-Security"),
	}
}

func buildSecurityFeatures(result *ExplainResult) ExplainSecurityFeatures {
	hsts := ExplainFeature{
		Available: result.HTTP.Available,
		Enabled:   false,
	}
	if result.HTTP.Available {
		hsts.Enabled = result.HTTP.HSTSHeader != ""
		if !hsts.Enabled {
			hsts.Details = "Strict-Transport-Security header missing"
		}
	} else {
		hsts.Details = "HTTP probe unavailable"
	}

	return ExplainSecurityFeatures{
		HSTS: hsts,
		OCSPStapling: ExplainFeature{
			Available: true,
			Enabled:   result.TLS.OCSPStapling,
		},
		SecureRenegotiation: ExplainFeature{
			Available: true,
			Enabled:   result.TLS.SecureRenegotiation,
		},
		ALPN: ExplainFeature{
			Available: true,
			Enabled:   result.Connection.ALPNProtocol != "",
			Details:   result.Connection.ALPNProtocol,
		},
	}
}

func computeGrade(result *ExplainResult) ExplainGrade {
	if !result.Certificate.ChainTrusted || !result.Certificate.HostnameMatch {
		reasons := make([]string, 0, 2)
		if !result.Certificate.ChainTrusted {
			reasons = append(reasons, "Certificate chain is not trusted")
		}
		if !result.Certificate.HostnameMatch {
			reasons = append(reasons, "Certificate hostname does not match target")
		}
		return ExplainGrade{
			Grade:   "F",
			Reasons: reasons,
		}
	}

	score := 0
	var reasons []string
	downgrade := func(reason string) {
		score++
		reasons = append(reasons, reason)
	}

	if versionLessThan12(result.TLS.ServerSelected) {
		downgrade("Negotiated TLS version is below TLS 1.2")
	}
	if result.Certificate.Expired || result.Certificate.NotYetValid {
		downgrade("Certificate validity window is not currently valid")
	}
	if !result.TLS.ForwardSecrecy {
		downgrade("Forward secrecy is not enabled")
	}
	if !result.Security.ALPN.Enabled {
		downgrade("ALPN negotiation missing")
	}
	if result.Certificate.DaysRemaining <= 30 {
		downgrade("Certificate expires in 30 days or less")
	}
	if result.HTTP.Available {
		if !result.Security.HSTS.Enabled {
			downgrade("HSTS header not present")
		}
	} else {
		downgrade("HTTP probe unavailable")
	}

	grades := []string{"A", "B", "C", "D", "E", "F"}
	if score >= len(grades) {
		score = len(grades) - 1
	}

	return ExplainGrade{
		Grade:   grades[score],
		Reasons: reasons,
	}
}

func versionLessThan12(v string) bool {
	switch v {
	case "TLS 1.3", "TLS 1.2":
		return false
	case "":
		return true
	default:
		return true
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case cryptotls.VersionTLS13:
		return "TLS 1.3"
	case cryptotls.VersionTLS12:
		return "TLS 1.2"
	case cryptotls.VersionTLS11:
		return "TLS 1.1"
	case cryptotls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("Unknown (0x%x)", v)
	}
}

func hasForwardSecrecy(version uint16, cipherSuite uint16) bool {
	if version == cryptotls.VersionTLS13 {
		return true
	}

	name := cryptotls.CipherSuiteName(cipherSuite)
	return strings.Contains(name, "_ECDHE_") || strings.Contains(name, "_DHE_")
}

func forwardSecrecyInfo(version uint16, cipherSuite uint16) string {
	if version == cryptotls.VersionTLS13 {
		return "TLS 1.3 ciphers always provide forward secrecy"
	}

	if hasForwardSecrecy(version, cipherSuite) {
		return "Ephemeral key exchange detected"
	}

	return "Cipher suite does not indicate ephemeral key exchange"
}

func keyExchangeMethod(version uint16, cipherSuite uint16, forwardSecrecy bool) string {
	if version == cryptotls.VersionTLS13 {
		return "ECDHE"
	}

	if forwardSecrecy {
		return "ECDHE"
	}

	name := cryptotls.CipherSuiteName(cipherSuite)
	if strings.Contains(name, "RSA") {
		return "RSA"
	}
	return "Unknown"
}

func curveName(curve cryptotls.CurveID) string {
	switch curve {
	case cryptotls.X25519MLKEM768:
		return "X25519MLKEM768"
	case cryptotls.X25519:
		return "X25519"
	case cryptotls.CurveP256:
		return "P-256"
	case cryptotls.CurveP384:
		return "P-384"
	case cryptotls.CurveP521:
		return "P-521"
	case 0:
		return "Unknown"
	default:
		return fmt.Sprintf("0x%x", uint16(curve))
	}
}
