// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"context"
	"net/netip"

	contract "github.com/daeuniverse/dae/api"
)

// SelectorStore owns live selections and their persistent overrides.
type SelectorStore interface {
	Selectors() []contract.SelectorState
	Select(group, node, source string) (contract.SelectorState, error)
}

type ProbeStore interface {
	Probe(contract.ProbeRequest, string) (contract.ProbeResponse, error)
}

type ScriptStore interface {
	TriggerScript(context.Context, string, contract.ScriptRunRequest) (contract.ScriptRunResponse, error)
}

type ScriptStoreMigrator interface {
	MigrateScriptStore(context.Context, string, contract.ScriptStoreMigrateRequest) (contract.ScriptStoreMigrateResponse, error)
}

// DeviceStore owns membership, MITM overrides, and atomic persistence.
type DeviceStore interface {
	HasClientSet(string) bool
	DeviceState(netip.Addr, [6]byte) contract.DeviceState
	UpdateClientSet(string, netip.Addr, [6]byte, bool) (contract.DeviceState, error)
	UpdateMITM(netip.Addr, [6]byte, *bool) (contract.DeviceState, error)
}
