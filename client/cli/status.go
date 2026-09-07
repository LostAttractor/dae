// SPDX-License-Identifier: AGPL-3.0-only

// Package cli contains API-only commands shared by dae and dae-client.
package cli

import (
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"fmt"
	"os"
	"time"

	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/client/status"
	"github.com/spf13/cobra"
)

func NewStatusCommand() *cobra.Command      { return newStatusCommand(false) }
func NewSurgeStatusCommand() *cobra.Command { return newStatusCommand(true) }

func newStatusCommand(surge bool) *cobra.Command {
	var endpoint string
	var timeout time.Duration
	var verbose, recent, raw bool
	command := &cobra.Command{
		Use: "status", Short: "Show the status of the running dae daemon through its API.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client.New(client.Options{Endpoint: endpoint, Token: os.Getenv("DAE_API_TOKEN"), Timeout: timeout})
			if err != nil {
				return err
			}
			defer c.Close()
			snapshot, err := c.Status(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get status: %w", err)
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), snapshot, jsonv1.FormatDurationAsNano(true))
			}
			if surge {
				report, err := status.Surge(snapshot.MITMPlugins)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), status.RenderSurge(report, true))
				return err
			}
			if recent {
				status.PrintRecent(cmd.OutOrStdout(), snapshot)
			} else {
				status.Print(cmd.OutOrStdout(), snapshot, verbose)
			}
			return nil
		},
	}
	defaultEndpoint := os.Getenv("DAE_API_ENDPOINT")
	if defaultEndpoint == "" {
		defaultEndpoint = client.DefaultEndpoint
	}
	command.Flags().StringVar(&endpoint, "api", defaultEndpoint, "API origin or unix:///absolute/socket/path (DAE_API_ENDPOINT)")
	command.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "API request timeout")
	command.Flags().BoolVar(&raw, "json", false, "print the API snapshot as JSON")
	if !surge {
		command.Flags().BoolVar(&verbose, "verbose", false, "show detailed network and path health")
		command.Flags().BoolVar(&recent, "recent", false, "show recent group connectivity")
		command.MarkFlagsMutuallyExclusive("verbose", "recent", "json")
	}
	return command
}
