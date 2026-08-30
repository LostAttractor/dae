// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestRoutingTupleMapLayout(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["routing_tuples_map"]
	if m == nil {
		t.Fatal("routing_tuples_map is missing")
	}
	if m.ValueSize != 40 {
		t.Fatalf("routing_tuples_map value size = %d, want 40", m.ValueSize)
	}
	var result bpfRoutingResult
	if size := unsafe.Sizeof(result); size != 40 {
		t.Fatalf("routing result layout size = %d, want 40", size)
	}
	cache := spec.Maps["udp_routing_cache_map"]
	if cache == nil {
		t.Fatal("udp_routing_cache_map is missing")
	}
	if cache.KeySize != 72 || cache.ValueSize != 48 {
		t.Fatalf("UDP routing cache layout = key %d, value %d; want 72, 48", cache.KeySize, cache.ValueSize)
	}
	var cacheValue bpfUdpRoutingCacheValue
	if size, offset := unsafe.Sizeof(cacheValue), unsafe.Offsetof(cacheValue.CachedUntil); size != 48 || offset != 40 {
		t.Fatalf("UDP routing cache value layout = size %d, cached_until offset %d; want 48, 40", size, offset)
	}
}

func TestDeleteUDPRoutingTuplesPreservesTCP(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "routing_tuple_test",
		Type:       ebpf.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(bpfTuplesKey{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfRoutingResult{})),
		MaxEntries: 8,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("creating an eBPF map requires privileges")
		}
		t.Fatal(err)
	}
	defer m.Close()

	udpKey := bpfTuplesKey{Sport: 1, L4proto: unix.IPPROTO_UDP}
	tcpProxyKey := bpfTuplesKey{Sport: 2, L4proto: unix.IPPROTO_TCP}
	tcpDirectKey := bpfTuplesKey{Sport: 3, L4proto: unix.IPPROTO_TCP}
	proxy := bpfRoutingResult{Outbound: 2}
	direct := bpfRoutingResult{Outbound: 0, Mark: 42}
	for key, value := range map[bpfTuplesKey]bpfRoutingResult{
		udpKey:       proxy,
		tcpProxyKey:  proxy,
		tcpDirectKey: direct,
	} {
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}

	if err := deleteUDPRoutingTuples(m); err != nil {
		t.Fatal(err)
	}
	var got bpfRoutingResult
	if err := m.Lookup(&udpKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("UDP lookup error = %v, want key not found", err)
	}
	if err := m.Lookup(&tcpProxyKey, &got); err != nil || got.Outbound != proxy.Outbound {
		t.Fatalf("TCP proxy tuple = %+v, %v; want preserved", got, err)
	}
	if err := m.Lookup(&tcpDirectKey, &got); err != nil || got.Mark != direct.Mark {
		t.Fatalf("TCP direct tuple = %+v, %v; want preserved", got, err)
	}
}

func TestDeleteUDPRoutingCache(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "udp_route_cache_test",
		Type:       ebpf.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(bpfUdpRoutingCacheKey{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfUdpRoutingCacheValue{})),
		MaxEntries: 8,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("creating an eBPF map requires privileges")
		}
		t.Fatal(err)
	}
	defer m.Close()

	value := bpfUdpRoutingCacheValue{CachedUntil: 1}
	for i := uint16(1); i <= 2; i++ {
		key := bpfUdpRoutingCacheKey{Tuples: bpfTuplesKey{Sport: i, L4proto: unix.IPPROTO_UDP}}
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	if err := deleteUDPRoutingCache(m); err != nil {
		t.Fatal(err)
	}
	var key bpfUdpRoutingCacheKey
	var got bpfUdpRoutingCacheValue
	if m.Iterate().Next(&key, &got) {
		t.Fatalf("UDP routing cache still contains key %+v", key)
	}
}
