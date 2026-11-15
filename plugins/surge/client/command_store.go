// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"encoding/json/v2"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/pkg/terminaltext"
	"github.com/spf13/cobra"
)

func NewSurgeStoreCommand(fetch cli.MITMSource, migrate cli.ScriptStoreMigrator) *cobra.Command {
	group := &cobra.Command{Use: "store", Short: "Manage device script storage in the daemon."}
	var raw bool
	command := &cobra.Command{
		Use: "migrate OLD_MAC NEW_MAC", Short: "Move a device's entire script storage partition to another MAC.",
		Long: `Move all persistentStore keys for one device in one Surge instance, without merging or overwriting.
Stop traffic and background tasks for the old MAC first. Device authorization is not changed.
A timeout or connection failure does not prove the move was not published; do not automatically retry.`,
		Args: cobra.ExactArgs(2), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			from, fromErr := net.ParseMAC(args[0])
			to, toErr := net.ParseMAC(args[1])
			if fromErr != nil || toErr != nil || len(from) != 6 || len(to) != 6 ||
				[6]byte(from) == [6]byte{} || [6]byte(to) == [6]byte{} || from[0]&1 != 0 || to[0]&1 != 0 || [6]byte(from) == [6]byte(to) {
				return fmt.Errorf("store migration requires two distinct nonzero unicast Ethernet MACs")
			}
			if fetch == nil || migrate == nil {
				return fmt.Errorf("script storage migration is unavailable")
			}
			response, err := cli.WithProgress(cmd, "Migrating script storage...", func() (*api.ScriptStoreMigrateResponse, error) {
				instances, err := fetch(cmd.Context())
				if err != nil {
					return nil, err
				}
				if len(instances.Plugins) != 1 {
					return nil, fmt.Errorf("store migration requires exactly one Surge instance; found %d, specify --instance", len(instances.Plugins))
				}
				return migrate(cmd.Context(), instances.Plugins[0].ID, api.ScriptStoreMigrateRequest{
					FromMAC: from.String(), ToMAC: to.String(),
				})
			})
			if err != nil {
				return err
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), response)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Moved %d keys in %s from %s to %s.\n", response.KeysMoved,
				terminaltext.Line(response.Instance), terminaltext.Line(response.FromMAC), terminaltext.Line(response.ToMAC))
			return err
		},
	}
	command.Flags().BoolVar(&raw, "json", false, "Print the migration result as JSON")
	group.AddCommand(command)
	return group
}
