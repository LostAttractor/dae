// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/control"
	"github.com/spf13/cobra"
)

func newRegistryCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "registry",
		Short: "Inspect persisted domain-IP evidence",
	}
	command.AddCommand(&cobra.Command{
		Use:   "dump [directory]",
		Short: "Print the persisted domain registry as JSON without changing it",
		Long: "Read the published baseline and replay its valid journal prefix. " +
			"Expired evidence is included. This is a disk view, not the running daemon's live state. " +
			"The directory defaults to DAE_LOCATION_CACHE or /var/lib/dae.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			dir := common.CacheDirectory()
			if len(args) != 0 {
				dir = args[0]
			}
			dump, err := control.InspectDomainRegistry(cmd.Context(), dir)
			if err != nil {
				return err
			}
			return json.MarshalEncode(jsontext.NewEncoder(cmd.OutOrStdout(), jsontext.WithIndent("  ")), dump)
		},
	})
	return command
}
