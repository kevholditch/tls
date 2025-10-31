package app

import (
	"io"

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
	cmd.AddCommand(NewReadCmd(stdOut, stdErr))

	return cmd
}
