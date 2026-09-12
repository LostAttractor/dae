// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The caller supplies expectations after building with make capacity overrides.
func TestConfiguredBPFMapCapacities(t *testing.T) {
	raw := os.Getenv("DAE_TEST_MAP_CAPACITIES")
	if raw == "" {
		t.Skip("set DAE_TEST_MAP_CAPACITIES after an override build")
	}
	var expected map[string]uint32
	if err := json.Unmarshal([]byte(raw), &expected); err != nil {
		t.Fatal(err)
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		m := spec.Maps[name]
		if m == nil || m.MaxEntries != want {
			t.Fatalf("%s: spec=%+v, want capacity=%d", name, m, want)
		}
	}
}

func TestRoutingTupleMapLayout(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	var result bpfRoutingResult
	if size := unsafe.Sizeof(result); size != 56 || spec.Maps["routing_tuples_map"].ValueSize != uint32(size) ||
		unsafe.Offsetof(result.Protocol) != 42 || unsafe.Offsetof(result.NoSniff) != 43 || unsafe.Offsetof(result.RouteEpoch) != 48 {
		t.Fatalf("routing result layout: size=%d protocol=%d no_sniff=%d route_epoch=%d", size, unsafe.Offsetof(result.Protocol), unsafe.Offsetof(result.NoSniff), unsafe.Offsetof(result.RouteEpoch))
	}
	cache := spec.Maps["udp_routing_cache_map"]
	var value bpfUdpRoutingCacheValue
	if cache.KeySize != uint32(unsafe.Sizeof(bpfUdpRoutingCacheKey{})) || cache.ValueSize != uint32(unsafe.Sizeof(value)) || unsafe.Offsetof(value.CachedUntil) != 32 || unsafe.Sizeof(value) != 64 || unsafe.Sizeof(value.Result) != 32 {
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
	if m.MaxEntries == 0 {
		t.Fatal("domain_routing_map capacity must be positive")
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

// Exercise the actual map metadata check, using pins isolated from dae state.
func TestRemoveIncompatiblePinnedMaps(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("pinning eBPF maps requires privileges")
	}
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "dae-routing-map-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(pinPath); err != nil {
			t.Error(err)
		}
	})
	spec := &ebpf.CollectionSpec{Maps: make(map[string]*ebpf.MapSpec)}
	for _, name := range []string{"compatible", "changed", "changed_flags", "unrelated"} {
		mapSpec := &ebpf.MapSpec{Name: name, Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
		if name == "changed_flags" {
			mapSpec.Type = ebpf.Hash
		}
		m, err := ebpf.NewMap(mapSpec)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		if err := m.Pin(filepath.Join(pinPath, name)); err != nil {
			t.Fatal(err)
		}
		if name == "unrelated" {
			continue
		}
		mapSpec.Pinning = ebpf.PinByName
		if name == "changed" {
			mapSpec.ValueSize = 8
		}
		if name == "changed_flags" {
			mapSpec.Flags = unix.BPF_F_NO_PREALLOC
		}
		spec.Maps[name] = mapSpec
	}
	for range 2 { // A removed pin is absent on the next load.
		if err := removeIncompatiblePinnedMaps(spec, pinPath); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"compatible", "changed", "changed_flags", "unrelated"} {
		_, err := os.Stat(filepath.Join(pinPath, name))
		if name == "changed" || name == "changed_flags" {
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("changed map was not removed: %v", err)
			}
		} else if err != nil {
			t.Fatalf("%s map was not preserved: %v", name, err)
		}
	}
}
