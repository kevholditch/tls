package cmd

import (
	"io"
	"time"

	"github.com/kevholditch/tls/internal/pretty"
	"github.com/kevholditch/tls/internal/tls"
	"github.com/spf13/cobra"
)

func NewReadCmd(stdOut, stdErr io.Writer) *cobra.Command {
	var mode string

	c := &cobra.Command{
		Use:   "read <target>",
		Short: "Read a certificate from a host or file",
		Long: `Read a certificate from a remote TLS endpoint or a local file.

Target can be:
  - hostname[:port]         e.g. example.com or example.com:8443
  - URL                     e.g. https://example.com
  - file path               e.g. ./cert.pem
  - "-" (stdin)             e.g. cat cert.pem | tls read -

Mode controls how target is interpreted:
  auto   - detect host vs file (default)
  file   - treat target as a file path
  server - treat target as a remote server`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			parsedMode, err := tls.ParseMode(mode)
			if err != nil {
				return err
			}

			cert, err := tls.Read(target, parsedMode)
			if err != nil {
				return err
			}
			return pretty.Print(stdOut, cert, time.Now())
		},
	}

	c.Flags().StringVar(&mode, "mode", "auto", "input mode: auto, file, or server")

	return c
}

