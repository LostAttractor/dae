// SPDX-License-Identifier: AGPL-3.0-only

// Package client provides Surge commands and report rendering without loading
// the script runtime. Command entry points register Commands explicitly.
package client

import (
	"fmt"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/cli"
	"github.com/spf13/cobra"
)

func Commands(fetch cli.MITMSource, trigger cli.ScriptTrigger) []*cobra.Command {
	return []*cobra.Command{NewSurgeStatusCommand(fetch), NewSurgeListCommand(fetch), NewSurgeRunCommand(fetch, trigger)}
}

func NewSurgeStatusCommand(fetch cli.MITMSource) *cobra.Command {
	var verbose bool
	command := cli.NewReportCommand(fetch, func(cmd *cobra.Command, instances api.PluginStatus) error {
		report, err := Surge(instances.Plugins)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), RenderSurge(report, verbose))
		return err
	})
	command.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show all retained notifications instead of the latest 3 per script")
	return command
}
