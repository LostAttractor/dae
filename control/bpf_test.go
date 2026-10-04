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
	if size := unsafe.Sizeof(result); size != 40 || spec.Maps["routing_tuples_map"].ValueSize != 48 || spec.Maps["tcp_flow_map"].ValueSize != 16 {
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
