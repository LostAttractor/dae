// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"net/netip"
	"slices"
	"sync"

	"github.com/daeuniverse/dae/common/macaddr"
)

var testDeviceMAC = [6]byte{2, 0, 0, 0, 0, 1}
var testLocalScope = ScriptScope{Kind: ScriptScopeLocal}
var testDeviceScope = testMACScope(testDeviceMAC)

func testMACScope(mac [6]byte) ScriptScope {
	return ScriptScope{Kind: ScriptScopeDevice, MAC: mac}
}

const testDeviceName = "02:00:00:00:00:01"

type testDeviceService struct {
	mu       sync.Mutex
	devices  [][6]byte
	identify func(context.Context, netip.Addr, [6]byte) [6]byte
	err      error
	queries  int
}

func newTestDevices(devices ...[6]byte) *testDeviceService {
	return &testDeviceService{devices: slices.Clone(devices)}
}

func (s *testDeviceService) Identify(ctx context.Context, ip netip.Addr, mac [6]byte) [6]byte {
	if s.identify != nil {
		return s.identify(ctx, ip, mac)
	}
	if macaddr.ValidClient(mac) {
		return mac
	}
	return [6]byte{}
}

func (s *testDeviceService) MITMEnabled(ctx context.Context) ([][6]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return slices.Clone(s.devices), s.err
}

func (s *testDeviceService) set(devices ...[6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = slices.Clone(devices)
}
