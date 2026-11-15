// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"net"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/component/plugin"
)

func (e *Engine) MigrateScriptStore(ctx context.Context, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
	from, fromErr := macaddr.ParseClient(request.FromMAC)
	to, toErr := macaddr.ParseClient(request.ToMAC)
	if fromErr != nil || toErr != nil || from == to {
		return api.ScriptStoreMigrateResponse{}, plugin.ErrScriptStoreInvalid
	}
	if e.options.Runtime == nil {
		return api.ScriptStoreMigrateResponse{}, plugin.ErrScriptStoreUnavailable
	}
	moved, err := e.options.Runtime.data.migrate(ctx, from, to)
	return api.ScriptStoreMigrateResponse{
		FromMAC: net.HardwareAddr(from[:]).String(), ToMAC: net.HardwareAddr(to[:]).String(), KeysMoved: moved,
	}, err
}
