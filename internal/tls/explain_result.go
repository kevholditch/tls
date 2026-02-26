package tls

import (
	"crypto/x509"
	"time"
)

type ExplainResult struct {
	Target      ExplainTarget
	DNS         ExplainDNS
	Connection  ExplainConnection
	TLS         ExplainTLS
	Certificate ExplainCertificate
	Security    ExplainSecurityFeatures
	HTTP        ExplainHTTP
	Grade       ExplainGrade
}

type ExplainTarget struct {
	Original string
	Host     string
	Port     int
	Address  string
	Protocol string
	IP       string
}

type ExplainDNS struct {
	Resolved bool
	IP       string
	Error    string
}

type ExplainConnection struct {
	TCPConnected bool
	TCPDuration  time.Duration
	ALPNProtocol string
	HTTP2        bool
}

type ExplainTLS struct {
	ClientOffered       []string
	ServerSelected      string
	CipherSuite         string
	ForwardSecrecy      bool
	ForwardSecrecyInfo  string
	KeyExchangeMethod   string
	KeyExchangeCurve    string
	OCSPStapling        bool
	SecureRenegotiation bool
}

type ExplainCertificate struct {
	Leaf           *x509.Certificate
	Chain          []*x509.Certificate
	VerifiedChains [][]*x509.Certificate
	Hostname       string
	HostnameMatch  bool
	HostnameError  string
	ChainTrusted   bool
	DaysRemaining  int
	ExpiresIn      time.Duration
	Expired        bool
	NotYetValid    bool
}

type ExplainFeature struct {
	Available bool
	Enabled   bool
	Details   string
}

type ExplainSecurityFeatures struct {
	HSTS                ExplainFeature
	OCSPStapling        ExplainFeature
	SecureRenegotiation ExplainFeature
	ALPN                ExplainFeature
}

type ExplainHTTP struct {
	Available   bool
	Protocol    string
	Compression string
	Server      string
	HSTSHeader  string
	Error       string
}

type ExplainGrade struct {
	Grade   string
	Reasons []string
}
