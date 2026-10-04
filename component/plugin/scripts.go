// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"errors"

	"github.com/daeuniverse/dae/api"
)

// ScriptTrigger queues an existing task under the plugin worker's lifetime.
// It returns promptly; closing the host must cancel and join accepted tasks.
type ScriptTrigger interface {
	TriggerScript(api.ScriptRunRequest) (api.ScriptRunResponse, error)
}

var (
	ErrScriptNotFound  = errors.New("script task or plugin instance not found")
	ErrScriptAmbiguous = errors.New("script task is ambiguous; specify a module")
	ErrScriptBusy      = errors.New("script task is already waiting or running")
	ErrScriptInactive  = errors.New("script worker is not active")
)
