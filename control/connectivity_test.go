/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func TestEncodeOutboundConnectivity(t *testing.T) {
	tests := []struct {
		name                   string
		alive                  bool
		noConnectivityTrySniff bool
		noConnectivityOutbound consts.OutboundIndex
		want                   uint32
	}{
		{
			name:                   "alive",
			alive:                  true,
			noConnectivityTrySniff: true,
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityAlive,
		},
		{
			name:                   "dead with try sniff",
			noConnectivityTrySniff: true,
			noConnectivityOutbound: consts.OutboundBlock,
			want:                   outboundConnectivityNoAliveTrySniff,
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
			got := encodeOutboundConnectivity(tt.alive, tt.noConnectivityTrySniff, tt.noConnectivityOutbound)
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
	if m.KeySize != 3 || m.ValueSize != 4 || m.MaxEntries != 256*2*2 {
		t.Fatalf("map shape = key:%d value:%d entries:%d, want 3/4/1024", m.KeySize, m.ValueSize, m.MaxEntries)
	}
}

func TestOutboundRecoveryCallbackFiresOnGlobalRecovery(t *testing.T) {
	core := new(controlPlaneCore)
	var recoveries atomic.Int32
	core.setOutboundRecoveryCallback(func() { recoveries.Add(1) })
	first := uint8(consts.OutboundUserDefinedMin)
	second := first + 1
	network := common.NetworkTCP4

	if callback := core.recordOutboundConnectivity(first, network, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 1 {
		t.Fatalf("recoveries = %d, want 1", got)
	}
	if callback := core.recordOutboundConnectivity(second, network, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 1 {
		t.Fatalf("second live outbound triggered recovery: %d", got)
	}

	core.recordOutboundConnectivity(first, network, false)
	core.recordOutboundConnectivity(second, network, false)
	if callback := core.recordOutboundConnectivity(second, network, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 2 {
		t.Fatalf("second global recovery count = %d, want 2", got)
	}
}

func TestOutboundRecoveryIsPerNetwork(t *testing.T) {
	core := new(controlPlaneCore)
	var recoveries atomic.Int32
	core.setOutboundRecoveryCallback(func() { recoveries.Add(1) })
	outbound := uint8(consts.OutboundUserDefinedMin)

	if callback := core.recordOutboundConnectivity(outbound, 0, true); callback != nil {
		callback()
	}
	if callback := core.recordOutboundConnectivity(outbound, 1, true); callback != nil {
		callback()
	}
	if got := recoveries.Load(); got != 2 {
		t.Fatalf("recoveries = %d, want one recovery per network", got)
	}
}

func TestOutboundUsableUsesRequestedNetwork(t *testing.T) {
	core := new(controlPlaneCore)
	outbound := uint8(consts.OutboundUserDefinedMin)
	tcp4 := common.NetworkTCP4
	udp6 := common.NetworkUDP6
	core.outboundConnectivityMap[outbound][tcp4].Store(true)
	core.outboundConnectivityMap[outbound][udp6].Store(false)

	if !core.outboundUsable(outbound, consts.L4ProtoType_TCP, consts.IpVersion_4) {
		t.Fatal("tcp4 was not usable")
	}
	if core.outboundUsable(outbound, consts.L4ProtoType_UDP, consts.IpVersion_6) {
		t.Fatal("udp6 inherited tcp4 availability")
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
		closed:                      closed,
		pendingOutboundConnectivity: make(map[bpfOutboundConnectivityQuery]uint32),
	}
	var recoveries int
	core.setOutboundRecoveryCallback(func() { recoveries++ })
	outbound := uint8(consts.OutboundUserDefinedMin)
	callback := core.outboundAliveChangeCallback(outbound, "proxy", false, consts.OutboundBlock)
	tcp4 := &common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	udp6 := &common.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6}
	for _, available := range []bool{false, true, false} {
		if err := callback(available, tcp4); err != nil {
			t.Fatal(err)
		}
		if got := core.outboundUsable(outbound, consts.L4ProtoType_TCP, consts.IpVersion_4); got != available {
			t.Fatalf("candidate tcp4 usability = %v, want %v", got, available)
		}
	}
	if err := callback(true, udp6); err != nil {
		t.Fatal(err)
	}
	if recoveries != 2 || len(core.pendingOutboundConnectivity) != 2 {
		t.Fatalf("recoveries = %d, pending networks = %d; want 2 each", recoveries, len(core.pendingOutboundConnectivity))
	}
	tcpKey := bpfOutboundConnectivityQuery{Outbound: outbound, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
	udpKey := bpfOutboundConnectivityQuery{Outbound: outbound, L4proto: unix.IPPROTO_UDP, Ipversion: 6}
	if core.pendingOutboundConnectivity[tcpKey] != outboundConnectivityNoAliveBlock || core.pendingOutboundConnectivity[udpKey] != outboundConnectivityAlive {
		t.Fatalf("pending state did not retain the latest result per network: %v", core.pendingOutboundConnectivity)
	}
	cancel()
	if err := callback(true, tcp4); !errors.Is(err, context.Canceled) {
		t.Fatalf("callback after closing = %v, want canceled", err)
	}
	if err := core.publishOutboundConnectivity(); !errors.Is(err, context.Canceled) {
		t.Fatalf("publish after closing = %v, want canceled", err)
	}
	if core.outboundConnectivityPublished || core.pendingOutboundConnectivity[tcpKey] != outboundConnectivityNoAliveBlock || recoveries != 2 {
		t.Fatal("closing changed prepared connectivity")
	}
}

func TestOutboundConnectivityPublication(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    3,
		ValueSize:  4,
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
		pendingOutboundConnectivity: make(map[bpfOutboundConnectivityQuery]uint32),
	}
	outbound := uint8(consts.OutboundUserDefinedMin)
	key := bpfOutboundConnectivityQuery{Outbound: outbound, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
	if err := m.Update(key, outboundConnectivityNoAliveDirect, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	callback := core.outboundAliveChangeCallback(outbound, "proxy", false, consts.OutboundBlock)
	network := &common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	if err := callback(true, network); err != nil {
		t.Fatal(err)
	}
	var value uint32
	if err := m.Lookup(key, &value); err != nil || value != outboundConnectivityNoAliveDirect {
		t.Fatalf("candidate changed old plane state: value = %d, error = %v", value, err)
	}
	if err := core.publishOutboundConnectivity(); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(key, &value); err != nil || value != outboundConnectivityAlive {
		t.Fatalf("published state = %d, error = %v; want alive", value, err)
	}
	if !core.outboundConnectivityPublished || core.pendingOutboundConnectivity != nil {
		t.Fatal("successful publication did not complete the transition")
	}
	if err := callback(false, network); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(key, &value); err != nil || value != outboundConnectivityNoAliveBlock {
		t.Fatalf("active callback state = %d, error = %v; want block", value, err)
	}
	if err := core.publishOutboundConnectivity(); err != nil {
		t.Fatalf("repeated publication: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := callback(true, network); err == nil {
		t.Fatal("active callback ignored a BPF write failure")
	}
	if core.outboundUsable(outbound, consts.L4ProtoType_TCP, consts.IpVersion_4) {
		t.Fatal("failed active BPF write changed userspace state")
	}
	core.outboundConnectivityPublished = false
	core.pendingOutboundConnectivity = map[bpfOutboundConnectivityQuery]uint32{key: outboundConnectivityAlive}
	if err := core.publishOutboundConnectivity(); err == nil {
		t.Fatal("publication ignored a BPF write failure")
	}
	if core.outboundConnectivityPublished || len(core.pendingOutboundConnectivity) != 1 {
		t.Fatal("failed publication discarded prepared connectivity")
	}
}
