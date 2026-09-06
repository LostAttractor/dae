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
	var result bpfRoutingResult
	if size := unsafe.Sizeof(result); size != 48 || spec.Maps["routing_tuples_map"].ValueSize != uint32(size) ||
		unsafe.Offsetof(result.Protocol) != 38 || unsafe.Offsetof(result.NoSniff) != 39 || unsafe.Offsetof(result.RouteEpoch) != 40 {
		t.Fatalf("routing result layout: size=%d protocol=%d no_sniff=%d route_epoch=%d", size, unsafe.Offsetof(result.Protocol), unsafe.Offsetof(result.NoSniff), unsafe.Offsetof(result.RouteEpoch))
	}
	cache := spec.Maps["udp_routing_cache_map"]
	var value bpfUdpRoutingCacheValue
	if cache.KeySize != uint32(unsafe.Sizeof(bpfUdpRoutingCacheKey{})) || cache.ValueSize != uint32(unsafe.Sizeof(value)) || unsafe.Offsetof(value.CachedUntil) != 48 {
		t.Fatalf("UDP cache layout: key=%d value=%d cached_until=%d", cache.KeySize, cache.ValueSize, unsafe.Offsetof(value.CachedUntil))
	}
}

func TestDomainRoutingMapSpec(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["domain_routing_map"]
	if m == nil {
		t.Fatal("domain_routing_map is missing")
	}
	if m.Type != ebpf.Hash {
		t.Fatalf("domain_routing_map type = %v, want hash", m.Type)
	}
	if m.Flags != unix.BPF_F_NO_PREALLOC {
		t.Fatalf("domain_routing_map flags = %#x, want BPF_F_NO_PREALLOC", m.Flags)
	}
	if m.MaxEntries != 65536 {
		t.Fatalf("domain_routing_map max entries = %d, want 65536", m.MaxEntries)
	}
	if m.KeySize != 16 || m.ValueSize != uint32(unsafe.Sizeof(bpfDomainRouting{})) {
		t.Fatalf("domain_routing_map layout = key %d, value %d; want 16, %d", m.KeySize, m.ValueSize, unsafe.Sizeof(bpfDomainRouting{}))
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
		key := bpfUdpRoutingCacheKey{Sport: i}
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	proxyKey := bpfUdpRoutingCacheKey{Sport: 3}
	value.Result.Outbound = 2
	if err := m.Update(&proxyKey, &value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := deleteUDPRoutingCache(m, true); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(&proxyKey, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("pending route survived reload: %v", err)
	}
	directKey := bpfUdpRoutingCacheKey{Sport: 1}
	if err := m.Lookup(&directKey, &value); err != nil {
		t.Fatalf("reload removed a direct lifetime: %v", err)
	}
	if err := deleteUDPRoutingCache(m, false); err != nil {
		t.Fatal(err)
	}
	var key bpfUdpRoutingCacheKey
	var got bpfUdpRoutingCacheValue
	if m.Iterate().Next(&key, &got) {
		t.Fatalf("UDP routing cache still contains key %+v", key)
	}
}

func newRoutingLayoutTestMap(t *testing.T, name string, maxEntries uint32) *ebpf.Map {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	ms := spec.Maps[name]
	ms.Pinning = ebpf.PinNone
	ms.MaxEntries = maxEntries
	m, err := ebpf.NewMap(ms)
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating an eBPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}
