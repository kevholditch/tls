package pretty

import (
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kevholditch/tls/internal/tls"
)

type errorWriter struct {
	w   io.Writer
	err error
}

func (ew *errorWriter) printKV(k, v string) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, "%s:\t%s\n", k, v)
}

func (ew *errorWriter) newLine() {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, "\t")
}

func formatDNS(names []string) string {
	if len(names) == 0 {
		return "[]"
	}

	var b strings.Builder
	b.WriteString("[\n\t\t")

	for i, n := range names {
		if i > 0 {
			b.WriteString(",\n\t\t")
		}
		b.WriteString(n)
	}

	b.WriteString("\n\t]")
	return b.String()
}

func certDisplayName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

func Print(writer io.Writer, result *tls.ReadResult, now time.Time) error {
	if result == nil || len(result.Chain) == 0 {
		return fmt.Errorf("no certificate in result")
	}
	cert := result.Chain[0]

	w := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)

	ew := &errorWriter{w: w}
	ew.newLine()
	ew.printKV("Common Name", cert.Subject.CommonName)
	ew.printKV("Subject", cert.Subject.String())
	ew.printKV("DNS Names", formatDNS(cert.DNSNames))

	ew.newLine()
	ew.printKV("Not Before", cert.NotBefore.Format(time.RFC3339))
	ew.printKV("Not After", cert.NotAfter.Format(time.RFC3339))
	ew.printKV("Expires In", expiresIn(cert.NotAfter.Sub(now)))

	ew.newLine()
	ew.printKV("Issuer", cert.Issuer.String())
	ew.printKV("Serial", cert.SerialNumber.String())

	ew.newLine()
	ew.printKV("Trust chain", "")
	for _, c := range result.Chain {
		trusted := tls.CertTrusted(c, result.Chain, result.VerifiedChains)
		mark := "✗"
		if trusted {
			mark = "✓"
		}
		_, ew.err = fmt.Fprintf(ew.w, "\t%s %s\n", mark, certDisplayName(c))
		if ew.err != nil {
			break
		}
	}

	if ew.err != nil {
		return ew.err
	}
	return w.Flush()
}

func expiresIn(expiresIn time.Duration) string {
	totalHours := int(expiresIn.Hours())
	days := totalHours / 24
	hours := totalHours % 24

	sign := "✅"
	if days < 7 {
		sign = "⚠️"
	}

	if days < 1 {
		return fmt.Sprintf("%s %d Hours", sign, hours)
	}

	return fmt.Sprintf("%s %d Days %d Hours", sign, days, hours)
}

func niceSigAlg(sa x509.SignatureAlgorithm) string {
	switch sa {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		return "RSA-SHA256"
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		return "RSA-SHA384"
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return "RSA-SHA512"
	case x509.SHA1WithRSA:
		return "RSA-SHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSA-SHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSA-SHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSA-SHA512"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return sa.String()
	}
}
