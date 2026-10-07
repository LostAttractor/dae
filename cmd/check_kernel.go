// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"os/signal"
	"syscall"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/control"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "check-kernel",
		Short: "Check kernel support and privileges without starting the daemon.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			if err := internal.AutoSu(); err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return control.CheckKernelFeatures(ctx)
		},
	})
}
