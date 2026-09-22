// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"errors"
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

// DeviceStore owns membership, MITM overrides, and atomic persistence.
type DeviceStore interface {
	HasClientSet(string) bool
	DeviceState(netip.Addr, [6]byte) contract.DeviceState
	UpdateClientSet(string, netip.Addr, [6]byte, bool) (contract.DeviceState, error)
	UpdateMITM(netip.Addr, [6]byte, *bool) (contract.DeviceState, error)
}

var (
	ErrSelectorNotFound  = errors.New("selector group not found")
	ErrSelectorNode      = errors.New("node_id is not a path in this selector")
	ErrSelectorNoDefault = errors.New("selector has no configured default")
	ErrProbeOutbound     = errors.New("probe outbound not found")
	ErrProbeNode         = errors.New("node_id is not a path in this outbound")
	ErrProbeUnsupported  = errors.New("outbound does not support connectivity probes")
)
