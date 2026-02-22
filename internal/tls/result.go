package tls

import (
	"crypto/x509"
	"time"
)

// isSelfSigned reports whether the certificate is self-signed (signed by its own key).
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// ReadResult holds the certificate chain and the result of verifying it against trusted roots.
type ReadResult struct {
	Chain          []*x509.Certificate
	VerifiedChains [][]*x509.Certificate
}

// verifyChain verifies the chain against the given roots and returns the verified chains.
// The chain is ordered leaf-first. Intermediates are built from chain[1:], but we exclude
// any self-signed (root) certs: if the server sent the root, putting it in Intermediates
// would make the verifier build a chain ending in that cert, which is not in the system
// Roots pool (different instance/serial), so verification would fail.
func verifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) [][]*x509.Certificate {
	if len(chain) == 0 || roots == nil {
		return nil
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		c := chain[i]
		if !isSelfSigned(c) {
			intermediates.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	verified, err := chain[0].Verify(opts)
	if err != nil {
		return nil
	}
	return verified
}

// CertTrusted reports whether the certificate should be shown as trusted.
// It is true if the cert appears in any verified chain. It is also true if
// the cert is the last in the display chain and at least one chain verified—
// the server may send its own copy of the root, which is not in VerifiedChains
// (the verifier uses the system's copy), but the chain verified so we show
// the root as trusted.
func CertTrusted(cert *x509.Certificate, chain []*x509.Certificate, verifiedChains [][]*x509.Certificate) bool {
	for _, ch := range verifiedChains {
		for _, c := range ch {
			if c.Equal(cert) {
				return true
			}
		}
	}
	if len(verifiedChains) == 0 {
		return false
	}
	// Last cert in chain (typically root sent by server) is trusted when verification succeeded.
	if len(chain) > 0 && cert.Equal(chain[len(chain)-1]) {
		return true
	}
	return false
}
