// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"errors"

	"github.com/daeuniverse/dae/api"
)

// ScriptTrigger queues an existing task under the plugin worker's lifetime.
// ctx bounds admission only; accepted tasks survive request cancellation.
// Closing the host must cancel and join accepted tasks.
type ScriptTrigger interface {
	TriggerScript(context.Context, api.ScriptRunRequest) (api.ScriptRunResponse, error)
}

var (
	ErrScriptNotFound          = errors.New("script task or plugin instance not found")
	ErrScriptAmbiguous         = errors.New("script task is ambiguous; specify a module")
	ErrScriptBusy              = errors.New("script task is already waiting or running")
	ErrScriptInactive          = errors.New("script worker is not active")
	ErrScriptDeviceUnsupported = errors.New("script does not isolate LAN clients; omit MAC")
	ErrScriptDeviceUnavailable = errors.New("script device discovery is unavailable")
	ErrScriptDeviceInvalid     = errors.New("script device MAC is invalid")
	ErrScriptDeviceDisabled    = errors.New("script device is not enabled for MITM")
)
