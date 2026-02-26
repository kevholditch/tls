package prettyprint

import (
	"fmt"
	"io"
	"strings"

	tlspkg "github.com/kevholditch/tls/internal/tls"
)

func ExplainResult(w io.Writer, result *tlspkg.ExplainResult) error {
	if result == nil || result.Certificate.Leaf == nil {
		return fmt.Errorf("no explanation result")
	}

	divider := "────────────────────────────────────────────────────────────"
	_, err := fmt.Fprintf(w, "\n%s\n TLS CONNECTION EXPLANATION\n%s\n\n", divider, divider)
	if err != nil {
		return err
	}

	leaf := result.Certificate.Leaf
	blocks := []outputBlock{
		{
			rows: []outputRow{
				kvRow("Target", result.Target.Host),
				kvRow("IP Address", valueOrNA(result.Target.IP)),
				kvRow("Port", fmt.Sprintf("%d", result.Target.Port)),
				kvRow("Protocol", result.Target.Protocol),
			},
		},
		{
			title:      "DNS",
			titleStyle: blockTitlePlain,
		},
		{
			title:      "Connection",
			titleStyle: blockTitlePlain,
		},
		{
			title:      "TLS NEGOTIATION",
			titleStyle: blockTitlePlain,
			rows: []outputRow{
				textRow(fmt.Sprintf("Client offered: %s", strings.Join(result.TLS.ClientOffered, ", "))),
			},
		},
		{
			title:      "Cipher Suite",
			titleStyle: blockTitlePlain,
		},
		{
			title:      "Key Exchange",
			titleStyle: blockTitlePlain,
		},
	}

	certificateBlocks := buildCertificateBlocks(leaf, result.Certificate.ExpiresIn, certificateBlockOptions{
		Title:      "CERTIFICATE",
		TitleStyle: blockTitlePlain,
	})
	blocks = append(blocks, certificateBlocks...)

	hostnameBlockIdx := len(blocks)
	blocks = append(blocks, outputBlock{
		title:      "Hostname Match",
		titleStyle: blockTitlePlain,
	})

	blocks = append(blocks, buildTrustChainBlock(result.Certificate.Chain, result.Certificate.VerifiedChains, trustChainBlockOptions{
		Title:                    "Trust chain",
		TitleStyle:               blockTitleKeyValue,
		IncludeValidationSummary: true,
		ChainTrusted:             result.Certificate.ChainTrusted,
	}))

	revocationBlockIdx := len(blocks)
	blocks = append(blocks, outputBlock{
		title:      "Revocation",
		titleStyle: blockTitlePlain,
	})

	securityFeaturesBlockIdx := len(blocks)
	blocks = append(blocks, outputBlock{
		title:      "SECURITY FEATURES",
		titleStyle: blockTitlePlain,
	})

	httpLayerBlockIdx := len(blocks)
	blocks = append(blocks, outputBlock{
		title:      "HTTP LAYER",
		titleStyle: blockTitlePlain,
	})

	gradeBlockIdx := len(blocks)
	blocks = append(blocks, outputBlock{
		title:      "OVERALL SECURITY RATING",
		titleStyle: blockTitlePlain,
	})

	if result.DNS.Resolved {
		blocks[1].rows = append(blocks[1].rows, textRow("✅ A record resolved"))
		blocks[1].rows = append(blocks[1].rows, textRow(fmt.Sprintf("  %s -> %s", result.Target.Host, result.DNS.IP)))
	} else {
		blocks[1].rows = append(blocks[1].rows, textRow("❌ DNS resolution failed"))
		blocks[1].rows = append(blocks[1].rows, textRow(fmt.Sprintf("  %s", valueOrNA(result.DNS.Error))))
	}

	if result.Connection.TCPConnected {
		blocks[2].rows = append(blocks[2].rows, textRow(fmt.Sprintf("✅ TCP connection established (%d ms)", result.Connection.TCPDuration.Milliseconds())))
	} else {
		blocks[2].rows = append(blocks[2].rows, textRow("❌ TCP connection failed"))
	}
	if result.Connection.HTTP2 {
		blocks[2].rows = append(blocks[2].rows, textRow("✅ Server supports HTTP/2"))
	} else {
		blocks[2].rows = append(blocks[2].rows, textRow("❌ Server did not negotiate HTTP/2"))
	}

	selectedLine := fmt.Sprintf("Server selected: %s", valueOrNA(result.TLS.ServerSelected))
	if result.TLS.ServerSelected == "TLS 1.3" {
		selectedLine += " ✅ (most secure available)"
	}
	blocks[3].rows = append(blocks[3].rows, textRow(selectedLine))

	blocks[4].rows = append(blocks[4].rows, kvRow("Selected", valueOrNA(result.TLS.CipherSuite)))
	blocks[4].rows = append(blocks[4].rows, textRow("Why this?"))
	if result.TLS.ForwardSecrecy {
		blocks[4].rows = append(blocks[4].rows, textRow("- Forward secrecy enabled"))
		blocks[4].rows = append(blocks[4].rows, kvRow("Security", "STRONG"))
	} else {
		blocks[4].rows = append(blocks[4].rows, textRow("- Forward secrecy not detected"))
		blocks[4].rows = append(blocks[4].rows, kvRow("Security", "WEAK"))
	}

	blocks[5].rows = append(blocks[5].rows, kvRow("Method", valueOrNA(result.TLS.KeyExchangeMethod)))
	blocks[5].rows = append(blocks[5].rows, kvRow("Curve", valueOrNA(result.TLS.KeyExchangeCurve)))
	if result.TLS.ForwardSecrecy {
		blocks[5].rows = append(blocks[5].rows, textRow("✅ Perfect Forward Secrecy enabled"))
		blocks[5].rows = append(blocks[5].rows, textRow("  (past traffic remains safe even if key leaks later)"))
	} else {
		blocks[5].rows = append(blocks[5].rows, textRow("❌ Perfect Forward Secrecy not detected"))
	}

	if result.Certificate.HostnameMatch {
		blocks[hostnameBlockIdx].rows = append(blocks[hostnameBlockIdx].rows, textRow(fmt.Sprintf("✅ Certificate SAN contains %s", result.Certificate.Hostname)))
	} else {
		blocks[hostnameBlockIdx].rows = append(blocks[hostnameBlockIdx].rows, textRow(fmt.Sprintf("❌ Certificate SAN does not match %s", result.Certificate.Hostname)))
	}
	stapling := "Absent ❌"
	if result.TLS.OCSPStapling {
		stapling = "Present ✅"
	}
	blocks[revocationBlockIdx].rows = append(blocks[revocationBlockIdx].rows, kvRow("OCSP Stapling", stapling))
	blocks[revocationBlockIdx].rows = append(blocks[revocationBlockIdx].rows, kvRow("Certificate status", certStatus(result.TLS.OCSPStapling)))

	blocks[securityFeaturesBlockIdx].rows = append(blocks[securityFeaturesBlockIdx].rows, textRow(fmt.Sprintf("%s HSTS %s", featureMark(result.Security.HSTS), featureValue(result.Security.HSTS))))
	blocks[securityFeaturesBlockIdx].rows = append(blocks[securityFeaturesBlockIdx].rows, textRow(fmt.Sprintf("%s OCSP stapling", featureMark(result.Security.OCSPStapling))))
	blocks[securityFeaturesBlockIdx].rows = append(blocks[securityFeaturesBlockIdx].rows, textRow(fmt.Sprintf("%s Secure renegotiation", featureMark(result.Security.SecureRenegotiation))))
	blocks[securityFeaturesBlockIdx].rows = append(blocks[securityFeaturesBlockIdx].rows, textRow(fmt.Sprintf("%s ALPN negotiation", featureMark(result.Security.ALPN))))

	if result.HTTP.Available {
		blocks[httpLayerBlockIdx].rows = append(blocks[httpLayerBlockIdx].rows, kvRow("Protocol", valueOrNA(result.HTTP.Protocol)))
		blocks[httpLayerBlockIdx].rows = append(blocks[httpLayerBlockIdx].rows, kvRow("Compression", valueOrNA(result.HTTP.Compression)))
		blocks[httpLayerBlockIdx].rows = append(blocks[httpLayerBlockIdx].rows, kvRow("Server", valueOrNA(result.HTTP.Server)))
	} else {
		blocks[httpLayerBlockIdx].rows = append(blocks[httpLayerBlockIdx].rows, kvRow("Protocol", "N/A"))
		blocks[httpLayerBlockIdx].rows = append(blocks[httpLayerBlockIdx].rows, kvRow("Compression", "N/A"))
		blocks[httpLayerBlockIdx].rows = append(blocks[httpLayerBlockIdx].rows, kvRow("Server", "N/A"))
	}

	blocks[gradeBlockIdx].rows = append(blocks[gradeBlockIdx].rows, kvRow("Grade", result.Grade.Grade))
	if len(result.Grade.Reasons) == 0 {
		blocks[gradeBlockIdx].rows = append(blocks[gradeBlockIdx].rows, textRow(""))
		blocks[gradeBlockIdx].rows = append(blocks[gradeBlockIdx].rows, textRow("No major issues detected."))
		return renderBlocks(w, blocks)
	}

	blocks[gradeBlockIdx].rows = append(blocks[gradeBlockIdx].rows, textRow(""))
	blocks[gradeBlockIdx].rows = append(blocks[gradeBlockIdx].rows, textRow("Findings"))
	for _, reason := range result.Grade.Reasons {
		blocks[gradeBlockIdx].rows = append(blocks[gradeBlockIdx].rows, textRow(fmt.Sprintf("- %s", reason)))
	}

	return renderBlocks(w, blocks)
}

func valueOrNA(v string) string {
	if strings.TrimSpace(v) == "" {
		return "N/A"
	}
	return v
}

func certStatus(stapled bool) string {
	if stapled {
		return "GOOD"
	}
	return "UNKNOWN"
}

func featureMark(feature tlspkg.ExplainFeature) string {
	if !feature.Available {
		return "N/A"
	}
	if feature.Enabled {
		return "✅"
	}
	return "❌"
}

func featureValue(feature tlspkg.ExplainFeature) string {
	if !feature.Available {
		return "(N/A)"
	}
	if feature.Enabled {
		return "enabled"
	}
	return "not detected"
}
