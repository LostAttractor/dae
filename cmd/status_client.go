// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import "github.com/daeuniverse/dae/client/cli"

func init() {
	rootCmd.AddCommand(cli.NewStatusCommand(), cli.NewSelectorCommand(), cli.NewExplainCommand(), cli.NewClientCommand())
}
