// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"encoding/json"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/spf13/cobra"
)

// Definition is the compile-time entry point. Commands is optional and must not
// initialize runtime resources; the CLI may be used without a running daemon.
type Definition struct {
	Setup    Setup
	Commands func(CommandServices) []*cobra.Command
}

// CommandServices queries the running daemon, scoped to the plugin type and
// optional --instance selection. BaseDir resolves local CLI resources.
type CommandServices struct {
	BaseDir string
	Status  func(context.Context) ([]InstanceStatus, error)
}

// InstanceStatus carries host state and the plugin's credential-free Report.
type InstanceStatus struct {
	BufferMemory     *membuffer.Status `json:"buffer_memory,omitempty"`
	ID               string            `json:"id"`
	Type             string            `json:"type"`
	State            string            `json:"state"`
	Scopes           int               `json:"scopes"`
	DestinationRules int               `json:"destination_rules"`
	Details          json.RawMessage   `json:"details,omitempty"`
}
