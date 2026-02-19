package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
)

// CertChain holds the result of building a signed certificate chain.
type CertChain struct {
	// TLSCert is the tls.Certificate ready to use in a TLS server config.
	// Its Certificate field contains the leaf DER bytes followed by the CA DER bytes.
	TLSCert tls.Certificate
	// LeafCert is the parsed leaf certificate.
	LeafCert *x509.Certificate
	// CACert is the parsed CA (issuer) certificate.
	CACert *x509.Certificate
}

// BuildSignedCertChain creates a two-certificate chain: a leaf cert signed by a CA cert.
// leafTemplate defines the end-entity certificate; caTemplate defines the CA certificate.
// The CA certificate is self-signed; the leaf certificate is signed by the CA.
func BuildSignedCertChain(leafTemplate, caTemplate *x509.Certificate) *CertChain {
	// Generate CA key and self-sign the CA cert.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}

	// Generate leaf key and sign the leaf cert with the CA.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		panic(err)
	}

	return &CertChain{
		TLSCert: tls.Certificate{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
		},
		LeafCert: leafCert,
		CACert:   caCert,
	}
}
