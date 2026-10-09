// SPDX-License-Identifier: AGPL-3.0-only

// dae-client can be built with CGO_ENABLED=0, without eBPF generation.
package main

import (
	"fmt"
	"os"

	"github.com/daeuniverse/dae/client/cli"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{Use: "dae-client", Short: "Independent clients for the dae API", SilenceErrors: true}
	root.AddCommand(cli.NewStatusCommand())
	root.AddCommand(cli.NewSelectorCommand())
	root.AddCommand(cli.NewMITMCommand())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
