// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/component/surgemodule"
	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newSurgeStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Show loaded Surge modules in the running daemon.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			internal.AutoSu()
			snapshot, err := fetchStatus()
			if err != nil {
				return fmt.Errorf("failed to get Surge status: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), renderSurgeStatus(snapshot.Surge, true))
			return err
		},
	}
}

func renderSurgeStatus(status surgemodule.Status, showWarnings bool) string {
	if !status.Enabled {
		return "Surge modules: disabled"
	}
	if len(status.Modules) == 0 {
		return "Surge modules: no modules configured"
	}
	rows := make([]table.Row, 0, len(status.Modules))
	var details strings.Builder
	for _, module := range status.Modules {
		rows = append(rows, table.Row{
			module.Name, module.State, module.Scripts, module.Hostnames, module.HostMappings,
			module.URLRewrites, module.HeaderRewrites, module.BodyRewrites,
			module.MapLocals, module.Rules, len(module.Warnings),
		})
		if module.Error != "" {
			fmt.Fprintf(&details, "\n%s: %s", module.Name, module.Error)
		}
		if showWarnings {
			for _, warning := range module.Warnings {
				fmt.Fprintf(&details, "\n%s: warning: %s", module.Name, warning)
			}
		}
	}
	return "Surge modules:\n" + renderLogTable(table.Row{
		"MODULE", "STATE", "SCRIPTS", "HOSTS", "IP MAPS", "URL", "HEADER", "BODY", "LOCAL", "RULES", "WARNINGS",
	}, rows) + details.String()
}

func logStartupSurgeStatus(status surgemodule.Status) {
	if !log.IsLevelEnabled(log.InfoLevel) {
		return
	}
	// Module warnings are already logged at warning level while loading.
	for _, line := range strings.Split(renderSurgeStatus(status, false), "\n") {
		log.Info(line)
	}
}
