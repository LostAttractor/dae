// SPDX-License-Identifier: AGPL-3.0-only

// dae-client can be built with CGO_ENABLED=0, without eBPF generation.
package main

import (
	"fmt"
	"os"

	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/client/webui"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{Use: "dae-client", Short: "Independent clients for the dae API", SilenceErrors: true}
	root.AddCommand(cli.NewStatusCommand())
	surge := &cobra.Command{Use: "surge", Short: "Surge module status"}
	surge.AddCommand(cli.NewSurgeStatusCommand())
	root.AddCommand(surge)
	var directory string
	web := &cobra.Command{Use: "web", Short: "Export the standalone Web application for same-origin hosting", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := webui.Export(directory); err != nil {
			return err
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "Web assets exported to", directory)
		return err
	}}
	web.Flags().StringVar(&directory, "output", "dae-web", "output directory")
	root.AddCommand(web)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
