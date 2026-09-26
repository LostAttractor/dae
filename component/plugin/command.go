// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"

	"github.com/daeuniverse/dae/api"
	"github.com/spf13/cobra"
)

// Definition is the compile-time entry point. Commands is optional and must not
// initialize runtime resources; the CLI may be used without a running daemon.
type Definition struct {
	// Configure parses and validates configuration without I/O, workers or
	// mutations to Spec.Config. The factory captures the resulting configuration.
	Configure func(Spec) (Factory, error)
	Commands  func(CommandServices) []*cobra.Command
}

// CommandServices queries the running daemon, scoped to the plugin type and
// optional --instance selection. BaseDir resolves local CLI resources.
type CommandServices struct {
	BaseDir string
	Status  func(context.Context) ([]InstanceStatus, error)
}

// InstanceStatus carries host state and the plugin's credential-free Report.
type InstanceStatus = api.PluginInstanceStatus
