package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// ChainResult holds the result of building a root → intermediate → leaf certificate chain.
type ChainResult struct {
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	Leaf         *x509.Certificate
	ServerCert   tls.Certificate
}

// BuildChain creates a root CA, an intermediate CA, and a leaf certificate.
// The root signs the intermediate, the intermediate signs the leaf.
// ServerCert is suitable for use with a TLS server (chain leaf + intermediate; private key is the leaf's).
func BuildChain() (*ChainResult, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * 365 * time.Hour)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:                pkix.Name{CommonName: "Test Root CA", Organization: []string{"Test Root Inc"}},
		NotBefore:              notBefore,
		NotAfter:               notAfter,
		KeyUsage:               x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                   true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA", Organization: []string{"Test Intermediate Inc"}},
		Issuer:                root.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		return nil, err
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "example.com", Organization: []string{"Test Corp"}},
		Issuer:                intermediate.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}

	return &ChainResult{
		Root:         root,
		Intermediate: intermediate,
		Leaf:         leaf,
		ServerCert: tls.Certificate{
			Certificate: [][]byte{leafDER, intermediateDER},
			PrivateKey:  leafKey,
		},
	}, nil
}
