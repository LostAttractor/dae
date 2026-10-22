/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func TestEncodeOutboundConnectivity(t *testing.T) {
	tests := []struct {
		name                   string
		alive                  bool
		admitted               bool
		noConnectivityOutbound consts.OutboundIndex
		want                   uint32
	}{
		{
			name:                   "alive",
			alive:                  true,
			admitted:               true,
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityAlive,
		},
		{
			name:                   "dead and admitted to userspace",
			admitted:               true,
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityNoAliveUserspace,
		},
		{
			name:                   "dead fallback direct",
			noConnectivityOutbound: consts.OutboundDirect,
			want:                   outboundConnectivityNoAliveDirect,
		},
		{
			name:                   "dead fallback block",
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityNoAliveBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeOutboundConnectivity(tt.alive, tt.admitted, tt.noConnectivityOutbound)
			if got != tt.want {
				t.Fatalf("encodeOutboundConnectivity() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestOutboundConnectivityMapUsesNetworkKey(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["outbound_connectivity_map"]
	if m == nil {
		t.Fatal("outbound_connectivity_map is missing")
	}
	if m.KeySize != 3 || m.ValueSize != 8 || m.MaxEntries != 256*2*2 {
		t.Fatalf("map shape = key:%d value:%d entries:%d, want 3/8/1024", m.KeySize, m.ValueSize, m.MaxEntries)
	}
}

// publishTestConnectivity returns a candidate core's connectivity callback for
// a user-defined outbound.
func publishTestConnectivity(t *testing.T, core *controlPlaneCore, id uint8) func(common.NetworkIndex, bool) {
	t.Helper()
	callback := core.outboundAliveChangeCallback(id, "proxy", false, consts.OutboundBlock)
	return func(network common.NetworkIndex, available bool) {
		t.Helper()
		if err := callback(outbound.Connectivity{Network: network.NetworkType(), Available: available}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOutboundRecoveryCallbackFiresOnGlobalRecovery(t *testing.T) {
	core := &controlPlaneCore{closed: t.Context()}
	var recoveries int
	core.setOutboundRecoveryCallback(func() { recoveries++ })
	first := publishTestConnectivity(t, core, uint8(consts.OutboundUserDefinedMin))
	second := publishTestConnectivity(t, core, uint8(consts.OutboundUserDefinedMin)+1)
	network := common.NetworkTCP4

	first(network, true)
	if recoveries != 1 {
		t.Fatalf("recoveries = %d, want 1", recoveries)
	}
	second(network, true)
	if recoveries != 1 {
		t.Fatalf("second live outbound triggered recovery: %d", recoveries)
	}

	first(network, false)
	second(network, false)
	second(network, true)
	if recoveries != 2 {
		t.Fatalf("second global recovery count = %d, want 2", recoveries)
	}
}

func TestOutboundRecoveryIsPerNetwork(t *testing.T) {
	core := &controlPlaneCore{closed: t.Context()}
	var recoveries int
	core.setOutboundRecoveryCallback(func() { recoveries++ })
	publish := publishTestConnectivity(t, core, uint8(consts.OutboundUserDefinedMin))

	publish(common.NetworkTCP4, true)
	publish(common.NetworkTCP6, true)
	if recoveries != 2 {
		t.Fatalf("recoveries = %d, want one recovery per network", recoveries)
	}
}

func TestOutboundAvailableFollowsPublishedConnectivity(t *testing.T) {
	alive := downloadTestGroup(t, "alive", nil)
	option := new(dialer.GlobalOption)
	unchecked := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: dnsPathDialer{}}), option, &dialer.Property{Name: "unchecked"}, true, "")
	unavailable := outbound.NewDialerGroup(option, "unavailable", outbound.GroupKindSelector, []*dialer.Dialer{unchecked}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
	t.Cleanup(func() { _ = unavailable.Close() })
	c := &ControlPlane{outbounds: []*outbound.DialerGroup{alive, alive, unavailable}}
	id := uint8(consts.OutboundUserDefinedMin)
	if !c.outboundAvailable(0, consts.L4ProtoType_UDP, consts.IpVersion_6) || c.outboundAvailable(id, consts.L4ProtoType_TCP, consts.IpVersion_4) {
		t.Fatal("availability differs from the groups' published connectivity")
	}
	if !c.outboundAvailable(id, 0, consts.IpVersion_4) || !c.outboundAvailable(id, consts.L4ProtoType_TCP, 0) {
		t.Fatal("an unknown network mask was treated as unavailable")
	}
}

func TestEncodeOutboundConnectivityRejectsInvalidFallback(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected invalid no-connectivity outbound to panic")
		}
	}()
	encodeOutboundConnectivity(false, false, consts.OutboundUserDefinedMin)
}

func TestCandidateConnectivityUpdatesUserspaceWithoutBPF(t *testing.T) {
	closed, cancel := context.WithCancel(context.Background())
	defer cancel()
	core := &controlPlaneCore{
		closed:                     closed,
		outboundConnectivityValues: make(map[bpfOutboundConnectivityQuery]bpfOutboundConnectivity),
	}
	var recoveries int
	core.setOutboundRecoveryCallback(func() { recoveries++ })
	id := uint8(consts.OutboundUserDefinedMin)
	callback := core.outboundAliveChangeCallback(id, "proxy", false, consts.OutboundBlock)
	tcp4 := &common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	udp6 := &common.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6}
	for _, available := range []bool{false, true, false} {
		if err := callback(outbound.Connectivity{Network: tcp4, Available: available}); err != nil {
			t.Fatal(err)
		}
		key := bpfOutboundConnectivityQuery{Outbound: id, L4proto: tcp4.L4Proto.ToL4Proto(), Ipversion: tcp4.IpVersion.ToIpVersion()}
		if got := core.outboundConnectivityValues[key].State == outboundConnectivityAlive; got != available {
			t.Fatalf("candidate tcp4 usability = %v, want %v", got, available)
		}
	}
	if err := callback(outbound.Connectivity{Network: udp6, Available: true}); err != nil {
		t.Fatal(err)
	}
	if recoveries != 2 || len(core.outboundConnectivityValues) != 2 {
		t.Fatalf("recoveries = %d, pending networks = %d; want 2 each", recoveries, len(core.outboundConnectivityValues))
	}
	tcpKey := bpfOutboundConnectivityQuery{Outbound: id, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
	udpKey := bpfOutboundConnectivityQuery{Outbound: id, L4proto: unix.IPPROTO_UDP, Ipversion: 6}
	if core.outboundConnectivityValues[tcpKey].State != outboundConnectivityNoAliveBlock || core.outboundConnectivityValues[udpKey].State != outboundConnectivityAlive {
		t.Fatalf("pending state did not retain the latest result per network: %v", core.outboundConnectivityValues)
	}
	cancel()
	if err := callback(outbound.Connectivity{Network: tcp4, Available: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("callback after closing = %v, want canceled", err)
	}
	if err := core.publishOutboundConnectivity(); !errors.Is(err, context.Canceled) {
		t.Fatalf("publish after closing = %v, want canceled", err)
	}
	if core.outboundConnectivityPublished || core.outboundConnectivityValues[tcpKey].State != outboundConnectivityNoAliveBlock || recoveries != 2 {
		t.Fatal("closing changed prepared connectivity")
	}
}

// With reroute_mode while_possible every flow of an unavailable group tries a name.
func TestUnavailableGroupAdmission(t *testing.T) {
	for _, whilePossible := range []bool{false, true} {
		core := &controlPlaneCore{
			closed:                     context.Background(),
			outboundConnectivityValues: make(map[bpfOutboundConnectivityQuery]bpfOutboundConnectivity),
		}
		id := uint8(consts.OutboundUserDefinedMin)
		callback := core.outboundAliveChangeCallback(id, "proxy", whilePossible, consts.OutboundDirect)
		key := bpfOutboundConnectivityQuery{Outbound: id, L4proto: unix.IPPROTO_UDP, Ipversion: 4}
		if err := callback(outbound.Connectivity{Network: common.NetworkUDP4.NetworkType()}); err != nil {
			t.Fatal(err)
		}
		want := outboundConnectivityNoAliveDirect
		if whilePossible {
			want = outboundConnectivityNoAliveUserspace
		}
		if got := core.outboundConnectivityValues[key].State; got != want {
			t.Fatalf("while_possible=%v: state %d, want %d", whilePossible, got, want)
		}
	}
}

func TestOutboundConnectivityPublication(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    3,
		ValueSize:  8,
		MaxEntries: 4,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("creating an eBPF map requires privileges")
		}
		t.Fatal(err)
	}
	defer m.Close()
	core := &controlPlaneCore{
		closed: context.Background(),
		bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{
			OutboundConnectivityMap: m,
		}}},
		outboundConnectivityValues: make(map[bpfOutboundConnectivityQuery]bpfOutboundConnectivity),
	}
	id := uint8(consts.OutboundUserDefinedMin)
	key := bpfOutboundConnectivityQuery{Outbound: id, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
	if err := m.Update(key, bpfOutboundConnectivity{State: outboundConnectivityNoAliveDirect}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	callback := core.outboundAliveChangeCallback(id, "proxy", false, consts.OutboundBlock)
	network := &common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	if err := callback(outbound.Connectivity{Network: network, Available: true}); err != nil {
		t.Fatal(err)
	}
	var value bpfOutboundConnectivity
	if err := m.Lookup(key, &value); err != nil || value.State != outboundConnectivityNoAliveDirect {
		t.Fatalf("candidate changed old plane state: value = %+v, error = %v", value, err)
	}
	if err := core.publishOutboundConnectivity(); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(key, &value); err != nil || value.State != outboundConnectivityAlive {
		t.Fatalf("published state = %+v, error = %v; want alive", value, err)
	}
	if !core.outboundConnectivityPublished {
		t.Fatal("successful publication did not complete the transition")
	}
	if err := callback(outbound.Connectivity{Network: network}); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(key, &value); err != nil || value.State != outboundConnectivityNoAliveBlock {
		t.Fatalf("active callback state = %+v, error = %v; want block", value, err)
	}
	if err := core.publishOutboundConnectivity(); err != nil {
		t.Fatalf("repeated publication: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := callback(outbound.Connectivity{Network: network, Available: true}); err == nil {
		t.Fatal("active callback ignored a BPF write failure")
	}
	if core.outboundConnectivityValues[key].State != outboundConnectivityNoAliveBlock {
		t.Fatal("failed active BPF write changed userspace state")
	}
	core.outboundConnectivityPublished = false
	if err := core.publishOutboundConnectivity(); err == nil {
		t.Fatal("publication ignored a BPF write failure")
	}
	if core.outboundConnectivityPublished || len(core.outboundConnectivityValues) != 1 {
		t.Fatal("failed publication discarded prepared connectivity")
	}
}
