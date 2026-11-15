// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/component/plugin"
)

type ScriptScopeKind uint8

const (
	ScriptScopeUnknown ScriptScopeKind = iota
	ScriptScopeLocal
	ScriptScopeDevice
)

// ScriptScope is the effective execution scope, not the original source in shared mode.
type ScriptScope struct {
	Kind ScriptScopeKind
	MAC  [6]byte
}

func (s ScriptScope) valid() bool {
	return s.Kind == ScriptScopeLocal && s.MAC == [6]byte{} || s.Kind == ScriptScopeDevice && macaddr.ValidClient(s.MAC)
}

func (s ScriptScope) name() string {
	if s.valid() {
		if s.Kind == ScriptScopeLocal {
			return "local"
		}
		return "device"
	}
	return "unknown"
}

func (s ScriptScope) deviceName() string {
	if s.Kind == ScriptScopeDevice && s.valid() {
		return net.HardwareAddr(s.MAC[:]).String()
	}
	return ""
}

func (s ScriptScope) key() string {
	if s.Kind == ScriptScopeLocal && s.valid() {
		return "local"
	}
	return s.deviceName()
}

func (e *Engine) isolateLAN(script *Script) bool {
	if script.IsolateLANSet {
		return script.IsolateLAN
	}
	return e.options.IsolateLAN
}

func (e *Engine) identifyScope(ctx context.Context, origin plugin.SourceOrigin, source netip.Addr, mac [6]byte) ScriptScope {
	switch origin {
	case plugin.SourceLocal:
		return ScriptScope{Kind: ScriptScopeLocal}
	case plugin.SourceLAN:
		if e.options.Devices != nil {
			mac = e.options.Devices.Identify(ctx, source, mac)
			if macaddr.ValidClient(mac) {
				return ScriptScope{Kind: ScriptScopeDevice, MAC: mac}
			}
		}
	}
	return ScriptScope{}
}

// Cache only source identity; scripts in one exchange may use different isolation policies.
type scriptScopeKey struct{}

func (e *Engine) requestScope(ctx context.Context, script *Script) ScriptScope {
	if !e.isolateLAN(script) {
		return ScriptScope{Kind: ScriptScopeLocal}
	}
	if identify, ok := ctx.Value(scriptScopeKey{}).(func(context.Context) ScriptScope); ok {
		return identify(ctx)
	}
	return ScriptScope{}
}
