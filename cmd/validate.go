/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "To validate dae config.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			if cfgFile == "" {
				return fmt.Errorf("argument --config or -c is required")
			}
			// Read config from --config cfgFile.
			_, _, err := readConfig(cfgFile)
			return err
		},
	}
)

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}
