/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/daemon"

	"github.com/spf13/cobra"
)

func newValidateCommand(definitions map[string]plugin.Definition) *cobra.Command {
	var configFile string
	command := &cobra.Command{
		Use:   "validate",
		Short: "To validate dae config.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			if configFile == "" {
				return fmt.Errorf("argument --config or -c is required")
			}
			conf, _, err := config.Load(configFile)
			if err != nil {
				return err
			}
			return daemon.ValidateConfig(cmd.Context(), conf, definitions)
		},
	}
	command.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file")
	return command
}
