package cmd

import (
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/kevholditch/tls/internal/prettyprint"
	tlspkg "github.com/kevholditch/tls/internal/tls"
	"github.com/spf13/cobra"
)

func NewExplainCmd(stdOut, stdErr io.Writer) *cobra.Command {
	c := &cobra.Command{
		Use:   "explain <target>",
		Short: "Explain the TLS security posture of a server",
		Long: `Analyze a live TLS endpoint and explain the connection, TLS negotiation,
certificate details, and security posture.

Target can be:
  - hostname[:port]         e.g. example.com or example.com:8443
  - URL                     e.g. https://example.com

This command only supports live servers. For certificate files use:
  tls read <file>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			if target == "-" || tlspkg.DetectMode(target) == tlspkg.ModeFile {
				return fmt.Errorf("explain only supports server targets; use `tls read <file>` for certificates")
			}

			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}

			result, err := tlspkg.Explain(target, roots, time.Now())
			if err != nil {
				return err
			}

			return prettyprint.ExplainResult(stdOut, result)
		},
	}

	return c
}
