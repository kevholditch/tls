package prettyprint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/kevholditch/tls/internal/tls"
)

func formatStringList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}

	var b strings.Builder
	b.WriteString("[\n\t\t")

	for i, n := range values {
		if i > 0 {
			b.WriteString(",\n\t\t")
		}
		b.WriteString(n)
	}

	b.WriteString("\n\t]")
	return b.String()
}

func formatCommaList(values []string) string {
	if len(values) == 0 {
		return "None"
	}
	return strings.Join(values, ", ")
}

func formatColonHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	s := hex.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

func formatSerialColonHex(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	bytes := serial.Bytes()
	if len(bytes) == 0 {
		return "00"
	}
	return formatColonHex(bytes)
}

func publicKeySummary(cert *x509.Certificate) string {
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA (%d bits)", pk.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA (%s, %d bits)", pk.Curve.Params().Name, pk.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func formatKeyUsage(usage x509.KeyUsage) string {
	names := make([]string, 0, 9)
	if usage&x509.KeyUsageDigitalSignature != 0 {
		names = append(names, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		names = append(names, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		names = append(names, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		names = append(names, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		names = append(names, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		names = append(names, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		names = append(names, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		names = append(names, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		names = append(names, "Decipher Only")
	}
	return formatCommaList(names)
}

func niceExtKeyUsage(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "Server Auth"
	case x509.ExtKeyUsageClientAuth:
		return "Client Auth"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC End System"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC Tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC User"
	case x509.ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft Server Gated Crypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape Server Gated Crypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "Microsoft Commercial Code Signing"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "Microsoft Kernel Code Signing"
	default:
		return fmt.Sprintf("Unknown (%d)", usage)
	}
}

func formatExtKeyUsage(cert *x509.Certificate) string {
	names := make([]string, 0, len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage))
	for _, usage := range cert.ExtKeyUsage {
		names = append(names, niceExtKeyUsage(usage))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		names = append(names, oid.String())
	}
	return formatCommaList(names)
}

func certDisplayName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

func ReadResult(writer io.Writer, result *tls.ReadResult, now time.Time) error {
	if result == nil || len(result.Chain) == 0 {
		return fmt.Errorf("no certificate in result")
	}

	leaf := result.Chain[0]
	blocks := buildCertificateBlocks(leaf, leaf.NotAfter.Sub(now), certificateBlockOptions{
		IncludeKeyUsage: true,
	})
	blocks = append(blocks, buildTrustChainBlock(result.Chain, result.VerifiedChains, trustChainBlockOptions{
		Title:      "Trust chain",
		TitleStyle: blockTitleKeyValue,
		IndentRows: true,
	}))

	return renderBlocks(writer, blocks)
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
