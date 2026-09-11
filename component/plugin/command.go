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
	Setup    Setup
	Commands func(CommandServices) []*cobra.Command
	// Validate optionally checks local configuration before any plugin setup or
	// network/resource preparation. It must be deterministic and side-effect
	// free: do not perform I/O, start workers, or mutate Spec.Config. Setup must
	// still validate its input for callers that invoke it directly.
	Validate func(Spec) error
}

// CommandServices queries the running daemon, scoped to the plugin type and
// optional --instance selection. BaseDir resolves local CLI resources.
type CommandServices struct {
	BaseDir string
	Status  func(context.Context) ([]InstanceStatus, error)
}

// InstanceStatus carries host state and the plugin's credential-free Report.
type InstanceStatus = api.PluginInstanceStatus
