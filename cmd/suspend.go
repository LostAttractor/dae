/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	suspendCmd = &cobra.Command{
		Use:   "suspend [pid]",
		Short: "To suspend dae. This command puts dae into no-load state. Recover it by 'dae reload'.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReloadCommand(cmd, args, true)
		},
	}
)

func parsePositivePID(raw string) (int, error) {
	pid, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid %q", raw)
	}
	return int(pid), nil
}

func init() {
	rootCmd.AddCommand(suspendCmd)
	suspendCmd.PersistentFlags().BoolVarP(&abort, "abort", "a", false, "Abort established connections.")
}
