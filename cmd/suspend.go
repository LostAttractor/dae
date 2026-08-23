/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/spf13/cobra"
)

var (
	suspendCmd = &cobra.Command{
		Use:   "suspend [pid]",
		Short: "To suspend dae. This command puts dae into no-load state. Recover it by 'dae reload'.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			if len(args) == 0 {
				_pid, err := os.ReadFile(PidFilePath)
				if err != nil {
					return fmt.Errorf("failed to read pid file: %w", err)
				}
				args = []string{strings.TrimSpace(string(_pid))}
			}
			pid, err := parsePositivePID(args[0])
			if err != nil {
				return err
			}
			internal.AutoSu()

			abortMarkerCreated := false
			cleanupAbortMarker := func() {
				if abortMarkerCreated {
					_ = os.Remove(AbortFile)
				}
			}
			if abort {
				f, err := os.OpenFile(AbortFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					return fmt.Errorf("failed to create abort marker: %w", err)
				}
				abortMarkerCreated = true
				if err = f.Close(); err != nil {
					cleanupAbortMarker()
					return fmt.Errorf("failed to close abort marker: %w", err)
				}
			}
			if err = syscall.Kill(pid, syscall.SIGUSR2); err != nil {
				cleanupAbortMarker()
				return fmt.Errorf("failed to signal dae: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "OK")
			return nil
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
