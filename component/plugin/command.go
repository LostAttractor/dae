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
	// Resources refreshes external inputs without creating a runtime instance.
	// Plugins consuming files or remote resources implement this capability so
	// reload can compare their contents before constructing a replacement.
	Resources func(context.Context, Spec, Services) (Resources, error)
	Commands  func(CommandServices) []*cobra.Command
}

// CommandServices supports daemon queries/actions and configuration helpers.
// Status is scoped by type and --instance. BaseDir resolves local resources.
type CommandServices struct {
	BaseDir       string
	Status        func(context.Context) ([]InstanceStatus, error)
	TriggerScript func(context.Context, string, api.ScriptRunRequest) (*api.ScriptRunResponse, error)
}

// InstanceStatus carries host state and the plugin's Report.
type InstanceStatus = api.PluginInstanceStatus
