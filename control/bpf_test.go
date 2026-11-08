// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

func TestCachedBPFSpecIsIndependent(t *testing.T) {
	first, err := loadBPFSpec()
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadBPFSpec()
	if err != nil {
		t.Fatal(err)
	}
	want := second.Maps["routing_tuples_map"].MaxEntries
	first.Maps["routing_tuples_map"].MaxEntries = 1
	if err := first.Variables["PARAM"].Set(bpfDaeParam{ControlPlanePid: 123}); err != nil {
		t.Fatal(err)
	}
	var param bpfDaeParam
	if err := second.Variables["PARAM"].Get(&param); err != nil {
		t.Fatal(err)
	}
	if second.Maps["routing_tuples_map"].MaxEntries != want || param.ControlPlanePid == 123 {
		t.Fatal("map or constant mutation escaped the private collection")
	}
}

func BenchmarkBPFSpec(b *testing.B) {
	for _, test := range []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{{"parse", loadBpf}, {"copy", loadBPFSpec}} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := test.load(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

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
	if size := unsafe.Sizeof(result); size != 40 || spec.Maps["routing_tuples_map"].ValueSize != 64 || spec.Maps["tcp_flow_map"].ValueSize != 24 {
		t.Fatalf("routing layouts: result=%d handoff=%d flow=%d", size, spec.Maps["routing_tuples_map"].ValueSize, spec.Maps["tcp_flow_map"].ValueSize)
	}
	cache := spec.Maps["udp_routing_cache_map"]
	var value bpfUdpRoutingCacheValue
	if cache.KeySize != uint32(unsafe.Sizeof(bpfUdpRoutingCacheKey{})) || cache.ValueSize != uint32(unsafe.Sizeof(value)) || unsafe.Offsetof(value.CachedUntil) != 40 || unsafe.Sizeof(value) != 72 || unsafe.Sizeof(value.Result) != 40 {
		t.Fatalf("UDP cache layout: key=%d value=%d cached_until=%d", cache.KeySize, cache.ValueSize, unsafe.Offsetof(value.CachedUntil))
	}
	// Validate every member against compiled C BTF, including tail padding.
	// Equal sizeof alone would miss reordered fields or generated padding bytes.
	for name, typ := range map[string]reflect.Type{
		"routing_result":          reflect.TypeFor[bpfRoutingResult](),
		"routing_handoff":         reflect.TypeFor[bpfRoutingHandoff](),
		"tcp_flow_state":          reflect.TypeFor[bpfTcpFlowState](),
		"udp_routing_cache_value": reflect.TypeFor[bpfUdpRoutingCacheValue](),
		"udp_routing_scratch":     reflect.TypeFor[bpfUdpRoutingScratch](),
	} {
		t.Run(name, func(t *testing.T) {
			var layout *btf.Struct
			if err := spec.Types.TypeByName(name, &layout); err != nil {
				t.Fatal(err)
			}
			var offset uintptr
			member := 0
			for i := range typ.NumField() {
				field := typ.Field(i)
				if field.Type.Size() == 0 {
					continue // structs.HostLayout
				}
				if field.Name == "_" || member >= len(layout.Members) {
					t.Fatalf("unexpected Go field/padding: %+v", field)
				}
				c := layout.Members[member]
				size, err := btf.Sizeof(c.Type)
				if err != nil || c.BitfieldSize != 0 || !strings.EqualFold(field.Name, strings.ReplaceAll(c.Name, "_", "")) ||
					field.Type.Size() != uintptr(size) || field.Offset != offset || uintptr(c.Offset) != offset*8 {
					t.Fatalf("member %s: Go=%+v C=%+v size=%d err=%v, want contiguous offset %d", field.Name, field, c, size, err, offset)
				}
				offset += field.Type.Size()
				member++
			}
			if member != len(layout.Members) || offset != typ.Size() || offset != uintptr(layout.Size) {
				t.Fatalf("tail padding or missing member: fields=%d/%d bytes=%d Go=%d C=%d", member, len(layout.Members), offset, typ.Size(), layout.Size)
			}
			t.Logf("C/Go size=%d bytes, no alignment holes", offset)
		})
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
	tests := []struct {
		name    string
		oldType ebpf.MapType
		next    *ebpf.MapSpec
		keep    bool
	}{
		{"compatible", ebpf.Array, &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}, true},
		{"value_size", ebpf.Array, &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}, false},
		{"key_size", ebpf.Hash, &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 4, MaxEntries: 1}, false},
		{"capacity", ebpf.Array, &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 2}, false},
		{"type", ebpf.Array, &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1}, false},
		{"flags", ebpf.Hash, &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1, Flags: unix.BPF_F_NO_PREALLOC}, false},
		{"unrelated", ebpf.Array, nil, true},
	}
	spec := &ebpf.CollectionSpec{Maps: make(map[string]*ebpf.MapSpec)}
	ids := make(map[string]ebpf.MapID)
	const contents = uint32(0x12345678)
	for _, test := range tests {
		name := test.name
		mapSpec := &ebpf.MapSpec{Name: name, Type: test.oldType, KeySize: 4, ValueSize: 4, MaxEntries: 1}
		m, err := ebpf.NewMap(mapSpec)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		if err := m.Pin(filepath.Join(pinPath, name)); err != nil {
			t.Fatal(err)
		}
		if err := m.Update(uint32(0), contents, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, ok := info.ID()
		if !ok {
			t.Fatal("kernel did not provide a map ID")
		}
		ids[name] = id
		if test.next != nil {
			test.next.Name, test.next.Pinning = name, ebpf.PinByName
			spec.Maps[name] = test.next
		}
	}
	for range 2 { // A removed pin is absent on the next load.
		if err := removeIncompatiblePinnedMaps(spec, pinPath); err != nil {
			t.Fatal(err)
		}
	}
	checkKept := func(name string, m *ebpf.Map) {
		t.Helper()
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		if id, ok := info.ID(); !ok || id != ids[name] {
			t.Fatalf("%s: replaced retained map %d with %d", name, ids[name], id)
		}
		var value uint32
		if err := m.Lookup(uint32(0), &value); err != nil || value != contents {
			t.Fatalf("%s: retained contents = %#x, %v; want %#x", name, value, err, contents)
		}
	}
	for _, test := range tests {
		name := test.name
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
		if !test.keep {
			if m != nil {
				m.Close()
			}
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s: incompatible pin was not removed: %v", name, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		checkKept(name, m)
		m.Close()
	}
	for range 2 {
		collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinPath}})
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range tests {
			if test.next == nil {
				continue
			}
			m := collection.Maps[test.name]
			if err := test.next.Compatible(m); err != nil {
				t.Fatalf("%s: rebuilt map does not match its new shape: %v", test.name, err)
			}
			if test.keep {
				checkKept(test.name, m)
			}
		}
		collection.Close()
	}
}

// The socket owner storage keeps the name of the cookie-keyed LRU it replaced.
// Loading over an upgraded pin directory drops the old LRU and pins the
// storage, which later loads reuse.
func TestSocketOwnerStorageIsReusedAcrossLoads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("pinning eBPF maps requires privileges")
	}
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "dae-owner-map-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(pinPath); err != nil {
			t.Error(err)
		}
	})
	full, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"socket_owner_map": full.Maps["socket_owner_map"]}}
	var pinned ebpf.MapID
	for range 2 {
		if err := removeIncompatiblePinnedMaps(spec, pinPath); err != nil {
			t.Fatal(err)
		}
		m, err := ebpf.NewMapWithOptions(spec.Maps["socket_owner_map"], ebpf.MapOptions{PinPath: pinPath})
		if err != nil {
			t.Fatal(err)
		}
		info, err := m.Info()
		m.Close()
		if err != nil {
			t.Fatal(err)
		}
		if info.Type != ebpf.SkStorage {
			t.Fatalf("pinned socket owner map type = %s", info.Type)
		}
		id, ok := info.ID()
		if !ok {
			t.Skip("map IDs unavailable")
		}
		if pinned != 0 && id != pinned {
			t.Fatalf("second load replaced the pinned storage: map %d, want %d", id, pinned)
		}
		pinned = id
	}
	entries, err := os.ReadDir(pinPath)
	if err != nil || len(entries) != 1 {
		t.Fatalf("pins after reload = %v, %v", entries, err)
	}
}
