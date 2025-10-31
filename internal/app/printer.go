package app

import (
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
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

func Print(writer io.Writer, cert *x509.Certificate, now time.Time) error {
	w := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)

	ew := &errorWriter{w: w}
	ew.newLine()
	ew.printKV("Common Name", cert.Subject.CommonName)
	ew.printKV("Subject", cert.Subject.String())
	ew.printKV("DNS Names", fmt.Sprintf("[%s]", strings.Join(cert.DNSNames, ",")))

	ew.newLine()
	ew.printKV("Not Before", cert.NotBefore.Format(time.RFC3339))
	ew.printKV("Not After", cert.NotAfter.Format(time.RFC3339))
	ew.printKV("Expires In", expiresIn(cert.NotAfter.Sub(now)))

	ew.newLine()
	ew.printKV("Issuer", cert.Issuer.String())
	ew.printKV("Serial", cert.SerialNumber.String())

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
