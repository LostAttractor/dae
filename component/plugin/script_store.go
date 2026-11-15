// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"errors"

	"github.com/daeuniverse/dae/api"
)

// ScriptStoreMigrator moves a device partition synchronously without changing device authorization or future execution scopes.
type ScriptStoreMigrator interface {
	MigrateScriptStore(context.Context, api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error)
}

var (
	ErrScriptStoreInvalid     = errors.New("store migration requires two distinct nonzero unicast Ethernet MACs")
	ErrScriptStoreNotFound    = errors.New("script store source or plugin instance not found")
	ErrScriptStoreConflict    = errors.New("script store target partition already exists")
	ErrScriptStoreBusy        = errors.New("source or target script scope is executing")
	ErrScriptStoreUnavailable = errors.New("script storage runtime is unavailable in this instance")
)
