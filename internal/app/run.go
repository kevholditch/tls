package app

import (
	"io"
	"time"

	"github.com/spf13/cobra"
)

func Run(stdOut, stdErr io.Writer, args []string) error {
	root := NewRootCmd(stdOut, stdErr)
	root.SetArgs(args)
	return root.Execute()
}

func NewRootCmd(stdOut, stdErr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tls",
		Short: "A friendly TLS certificate inspector",
		Long:  "tls is a human-friendly CLI for inspecting TLS certificates from hosts and files.",
	}

	// Make Cobra write to your injected writers
	cmd.SetOut(stdOut)
	cmd.SetErr(stdErr)

	// Add subcommands
	cmd.AddCommand(newReadCmd(stdOut, stdErr))

	return cmd
}

func newReadCmd(stdOut, stdErr io.Writer) *cobra.Command {
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

			cert, err := Read(target)
			if err != nil {
				return err
			}
			return Print(stdOut, cert, time.Now())
		},
	}

	c.Flags().StringVar(&mode, "mode", "auto", "input mode: auto, file, or server")

	return c
}
