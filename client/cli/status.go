// SPDX-License-Identifier: AGPL-3.0-only

// Package cli contains API-only commands shared by dae and dae-client.
package cli

import (
	jsonv1 "encoding/json"
	json "encoding/json/v2"

	"github.com/daeuniverse/dae/client/status"
	"github.com/spf13/cobra"
)

func NewStatusCommand() *cobra.Command {
	var connection Connection
	var verbose, recent, raw bool
	var colorMode string
	command := &cobra.Command{
		Use: "status", Short: "Show the status of the running dae daemon through its API.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := status.SetColorMode(colorMode); err != nil {
				return err
			}
			snapshot, err := connection.Status(cmd.Context())
			if err != nil {
				return err
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), snapshot, jsonv1.FormatDurationAsNano(true))
			}
			if recent {
				status.PrintRecent(cmd.OutOrStdout(), snapshot)
			} else {
				status.Print(cmd.OutOrStdout(), snapshot, verbose)
			}
			return nil
		},
	}
	connection.Bind(command.Flags())
	command.Flags().StringVar(&colorMode, "color", "auto", "when to use colors: auto, always, or never")
	command.Flags().BoolVar(&raw, "json", false, "print the API snapshot as JSON")
	command.Flags().BoolVar(&verbose, "verbose", false, "show detailed network and path health")
	command.Flags().BoolVar(&recent, "recent", false, "show group selections, recent connectivity and traffic")
	command.MarkFlagsMutuallyExclusive("verbose", "recent", "json")
	return command
}
