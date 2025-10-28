package app

import (
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

func Print(writer io.Writer, cert *x509.Certificate, now time.Time) error {
	w := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	defer w.Flush()

	newLine(w)
	printKV(w, "Common Name", cert.Subject.CommonName)
	printKV(w, "Subject", cert.Subject.String())
	printKV(w, "DNS Names", fmt.Sprintf("[%s]", strings.Join(cert.DNSNames, ",")))

	newLine(w)
	printKV(w, "Not Before", cert.NotBefore.Format(time.RFC3339))
	printKV(w, "Not After", cert.NotAfter.Format(time.RFC3339))

	newLine(w)
	printKV(w, "Issuer", cert.Issuer.String())
	printKV(w, "Serial", cert.SerialNumber.String())

	return nil
}

func printKV(w io.Writer, k, v string) error {
	_, err := fmt.Fprintf(w, "%s:\t%s\n", k, v)
	return err
}

func newLine(w io.Writer) error {
	_, err := fmt.Fprintln(w, "\t")
	return err
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
