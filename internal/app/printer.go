package app

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func Print(cert *x509.Certificate, writer io.Writer, notAfter time.Time) error {
	w := bufio.NewWriter(writer)

	// Define styles
	headerBorder := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(lipgloss.Color("#00A3CC")).
		Padding(0, 1)

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00A3CC")).
		Align(lipgloss.Center)

	key := lipgloss.NewStyle().Width(12).Align(lipgloss.Left).
		Foreground(lipgloss.Color("#888888")) // grey

	colon := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888888")) // grey

	value := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")) // white

	warning := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFD700")) // yellow

	// Build header box
	header := title.Render("TLS Certificate")
	headerBox := headerBorder.Render(header)

	// Build certificate fields
	fields := []string{
		formatField(key, colon, value, "Host", getHost(cert)),
		formatField(key, colon, value, "Subject", formatDN(cert.Subject)),
		formatField(key, colon, value, "SANs", formatSANs(cert.DNSNames)),
		formatField(key, colon, value, "Issuer", formatDN(cert.Issuer)),
		formatField(key, colon, value, "Validity", formatValidity(cert.NotBefore, cert.NotAfter, notAfter, warning)),
		formatField(key, colon, value, "Serial", formatSerial(cert.SerialNumber)),
		formatField(key, colon, value, "Version", formatVersion(cert.Version)),
		formatField(key, colon, value, "Public Key", formatPublicKey(cert.PublicKey)),
		formatField(key, colon, value, "Sig Alg", niceSigAlg(cert.SignatureAlgorithm)),
		formatField(key, colon, value, "Key Usage", formatKeyUsage(cert.KeyUsage)),
		formatField(key, colon, value, "Ext Usage", formatExtKeyUsage(cert.ExtKeyUsage)),
		formatField(key, colon, value, "BasicConstr", formatBasicConstraints(cert.IsCA, cert.MaxPathLen)),
	}

	body := lipgloss.JoinVertical(lipgloss.Left, fields...)

	// Combine header and body
	content := lipgloss.JoinVertical(lipgloss.Left, headerBox, body)

	_, err := w.WriteString(content)
	if err != nil {
		return err
	}
	return w.Flush()
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

func formatField(key, colon, value lipgloss.Style, fieldName, fieldValue string) string {
	return lipgloss.JoinHorizontal(lipgloss.Top,
		key.Render(fieldName),
		colon.Render(" : "),
		value.Render(fieldValue))
}

func getHost(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.CommonName
}

func formatDN(name pkix.Name) string {
	var parts []string

	if name.CommonName != "" {
		parts = append(parts, "CN="+name.CommonName)
	}
	if len(name.Organization) > 0 {
		parts = append(parts, "O="+name.Organization[0])
	}
	if len(name.Country) > 0 {
		parts = append(parts, "C="+name.Country[0])
	}
	if len(name.OrganizationalUnit) > 0 {
		parts = append(parts, "OU="+name.OrganizationalUnit[0])
	}
	if len(name.Locality) > 0 {
		parts = append(parts, "L="+name.Locality[0])
	}
	if len(name.Province) > 0 {
		parts = append(parts, "ST="+name.Province[0])
	}

	return strings.Join(parts, ", ")
}

func formatSANs(dnsNames []string) string {
	if len(dnsNames) == 0 {
		return ""
	}
	return strings.Join(dnsNames, ", ")
}

func formatValidity(notBefore, notAfter, currentTime time.Time, warning lipgloss.Style) string {
	notBeforeStr := notBefore.Format("2006-01-02 15:04:05Z")
	notAfterStr := notAfter.Format("2006-01-02 15:04:05Z")

	validity := fmt.Sprintf("%s  →  %s", notBeforeStr, notAfterStr)

	// Check if certificate expires within 30 days
	daysUntilExpiry := int(notAfter.Sub(currentTime).Hours() / 24)
	if daysUntilExpiry < 30 && daysUntilExpiry >= 0 {
		warningText := fmt.Sprintf(" ⚠ expires in %d days", daysUntilExpiry)
		validity += warning.Render(warningText)
	}

	return validity
}

func formatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}

	hex := fmt.Sprintf("%X", serial.Bytes())
	// Add colons every 2 characters
	var result strings.Builder
	for i, char := range hex {
		if i > 0 && i%2 == 0 {
			result.WriteString(":")
		}
		result.WriteRune(char)
	}
	return result.String()
}

func formatVersion(version int) string {
	switch version {
	case 1:
		return "1 (X.509v1)"
	case 2:
		return "2 (X.509v2)"
	case 3:
		return "3 (X.509v3)"
	default:
		return fmt.Sprintf("%d (X.509v%d)", version, version)
	}
}

func formatPublicKey(key any) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d (%d bits)", k.N.BitLen(), k.N.BitLen())
	case *ecdsa.PublicKey:
		curve := k.Curve.Params().Name
		bits := k.Curve.Params().BitSize
		return fmt.Sprintf("ECDSA %s (%d bits)", curve, bits)
	default:
		return "Unknown"
	}
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var usages []string

	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}

	if len(usages) == 0 {
		return "None"
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(eku []x509.ExtKeyUsage) string {
	var usages []string

	for _, usage := range eku {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		default:
			usages = append(usages, "Unknown")
		}
	}

	if len(usages) == 0 {
		return "None"
	}
	return strings.Join(usages, ", ")
}

func formatBasicConstraints(isCA bool, maxPathLen int) string {
	caStatus := "false"
	if isCA {
		caStatus = "true"
	}

	pathLen := "—"
	if isCA && maxPathLen >= 0 {
		pathLen = fmt.Sprintf("%d", maxPathLen)
	}

	return fmt.Sprintf("CA=%s, pathlen=%s", caStatus, pathLen)
}
