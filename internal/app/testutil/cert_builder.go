package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

type CertBuilder struct {
	cert *x509.Certificate
}

func NewCertBuilder() *CertBuilder {
	return &CertBuilder{
		cert: &x509.Certificate{},
	}
}

func (cb *CertBuilder) WithDefault() *CertBuilder {
	cb.cert =
		&x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Test Corp"},
				CommonName:   "example.com",
			},
			Issuer: pkix.Name{
				CommonName: "Root CA Inc",
				Organization: []string{
					"Root CA Inc",
				},
			},
			SignatureAlgorithm:    x509.SHA256WithRSA,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
	return cb
}

// WithSerialNumber sets the certificate serial number
func (cb *CertBuilder) WithSerialNumber(serial *big.Int) *CertBuilder {
	cb.cert.SerialNumber = serial
	return cb
}

// WithSubject sets the subject using a custom function
func (cb *CertBuilder) WithSubject(create func() pkix.Name) *CertBuilder {
	cb.cert.Subject = create()
	return cb
}

// WithCommonName sets just the common name
func (cb *CertBuilder) WithCommonName(cn string) *CertBuilder {
	cb.cert.Subject.CommonName = cn
	return cb
}

// WithOrganization sets the organization
func (cb *CertBuilder) WithOrganization(org ...string) *CertBuilder {
	cb.cert.Subject.Organization = org
	return cb
}

// WithValidity sets NotBefore and NotAfter
func (cb *CertBuilder) WithValidity(notBefore, notAfter time.Time) *CertBuilder {
	cb.cert.NotBefore = notBefore
	cb.cert.NotAfter = notAfter
	return cb
}

// WithValidityDuration sets validity starting from now
func (cb *CertBuilder) WithValidityDuration(duration time.Duration) *CertBuilder {
	cb.cert.NotBefore = time.Now()
	cb.cert.NotAfter = time.Now().Add(duration)
	return cb
}

// WithKeyUsage sets the key usage flags
func (cb *CertBuilder) WithKeyUsage(usage x509.KeyUsage) *CertBuilder {
	cb.cert.KeyUsage = usage
	return cb
}

// WithExtKeyUsage sets the extended key usage
func (cb *CertBuilder) WithExtKeyUsage(usage ...x509.ExtKeyUsage) *CertBuilder {
	cb.cert.ExtKeyUsage = usage
	return cb
}

// WithDNSNames sets the DNS SANs
func (cb *CertBuilder) WithDNSNames(names ...string) *CertBuilder {
	cb.cert.DNSNames = names
	return cb
}

// WithIPAddresses sets the IP SANs
func (cb *CertBuilder) WithIPAddresses(ips ...net.IP) *CertBuilder {
	cb.cert.IPAddresses = ips
	return cb
}

// WithCA marks this as a CA certificate
func (cb *CertBuilder) WithCA(isCA bool) *CertBuilder {
	cb.cert.IsCA = isCA
	cb.cert.BasicConstraintsValid = true
	if isCA {
		cb.cert.KeyUsage |= x509.KeyUsageCertSign
	}
	return cb
}

// WithMaxPathLen sets the maximum path length for CA certificates
func (cb *CertBuilder) WithMaxPathLen(maxPathLen int) *CertBuilder {
	cb.cert.MaxPathLen = maxPathLen
	cb.cert.MaxPathLenZero = maxPathLen == 0
	return cb
}

func (cb *CertBuilder) BuildCert() *x509.Certificate {
	return cb.cert
}

// Build returns the built certificate
func (cb *CertBuilder) Build() tls.Certificate {

	// Generate test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, cb.cert, cb.cert, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}
