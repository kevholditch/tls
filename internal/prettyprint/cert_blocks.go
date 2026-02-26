package prettyprint

import (
	"crypto/x509"
	"fmt"
	"time"

	tlspkg "github.com/kevholditch/tls/internal/tls"
)

type certificateBlockOptions struct {
	Title           string
	TitleStyle      blockTitleStyle
	IncludeKeyUsage bool
}

func buildCertificateBlocks(cert *x509.Certificate, certExpiresIn time.Duration, opts certificateBlockOptions) []outputBlock {
	if cert == nil {
		return nil
	}

	blocks := []outputBlock{
		{
			title:      opts.Title,
			titleStyle: opts.TitleStyle,
			rows: []outputRow{
				kvRow("Subject", cert.Subject.String()),
				kvRow("DNS Names", formatStringList(cert.DNSNames)),
			},
		},
		{
			rows: []outputRow{
				kvRow("Not Before", cert.NotBefore.Format(time.RFC3339)),
				kvRow("Not After", cert.NotAfter.Format(time.RFC3339)),
				kvRow("Expires In", expiresIn(certExpiresIn)),
			},
		},
		{
			rows: []outputRow{
				kvRow("Issuer", cert.Issuer.String()),
				kvRow("Serial", formatSerialColonHex(cert.SerialNumber)),
				kvRow("Signature Algorithm", niceSigAlg(cert.SignatureAlgorithm)),
				kvRow("Public Key", publicKeySummary(cert)),
			},
		},
	}

	if opts.IncludeKeyUsage {
		blocks = append(blocks, outputBlock{
			rows: []outputRow{
				kvRow("Key Usage", formatKeyUsage(cert.KeyUsage)),
				kvRow("Extended Key Usage", formatExtKeyUsage(cert)),
			},
		})
	}

	return blocks
}

type trustChainBlockOptions struct {
	Title                    string
	TitleStyle               blockTitleStyle
	IndentRows               bool
	IncludeValidationSummary bool
	ChainTrusted             bool
}

func buildTrustChainBlock(chain []*x509.Certificate, verifiedChains [][]*x509.Certificate, opts trustChainBlockOptions) outputBlock {
	block := outputBlock{
		title:      opts.Title,
		titleStyle: opts.TitleStyle,
	}

	for _, c := range chain {
		mark := "❌"
		if tlspkg.CertTrusted(c, chain, verifiedChains) {
			mark = "✅"
		}
		line := fmt.Sprintf("%s %s", mark, certDisplayName(c))
		if opts.IndentRows {
			block.rows = append(block.rows, indentedTextRow(line))
		} else {
			block.rows = append(block.rows, textRow(line))
		}
	}

	if opts.IncludeValidationSummary {
		block.rows = append(block.rows, textRow(""))
		if opts.ChainTrusted {
			block.rows = append(block.rows, textRow("✅ Chain successfully validated against system trust store"))
		} else {
			block.rows = append(block.rows, textRow("❌ Chain validation failed against system trust store"))
		}
	}

	return block
}
