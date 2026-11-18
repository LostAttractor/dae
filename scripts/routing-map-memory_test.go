//go:build ignore

// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestProductionMapCoverage(t *testing.T) {
	paths, err := filepath.Glob("../control/bpf_bpf*.o")
	if err != nil || len(paths) == 0 {
		t.Fatalf("run make ebpf before testing: ELF paths=%v err=%v", paths, err)
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec(path)
			if err != nil {
				t.Fatalf("run make ebpf before testing: %v", err)
			}
			if err := validateMaps(spec); err != nil {
				t.Fatal(err)
			}
			for _, name := range requiredMaps {
				t.Run("missing/"+name, func(t *testing.T) {
					missing := spec.Copy()
					delete(missing.Maps, name)
					var out bytes.Buffer
					if err := measureMaps(&out, missing); err == nil || !strings.Contains(err.Error(), name) {
						t.Fatalf("missing map was not rejected: %v", err)
					}
					if out.Len() != 0 {
						t.Fatalf("measurement started before validation: %s", out.String())
					}
				})
			}
			for _, change := range []struct {
				name   string
				mutate func(*ebpf.CollectionSpec)
			}{
				{"missing inner", func(s *ebpf.CollectionSpec) { s.Maps["device_routes_map"].InnerMap = nil }},
				{"wrong outer type", func(s *ebpf.CollectionSpec) { s.Maps["device_routes_map"].Type = ebpf.Array }},
				{"unsupported inner", func(s *ebpf.CollectionSpec) { s.Maps["device_routes_map"].InnerMap.Type = ebpf.LPMTrie }},
				{"unsupported required map", func(s *ebpf.CollectionSpec) { s.Maps["tcp_flow_map"].Type = ebpf.SkStorage }},
			} {
				t.Run(change.name, func(t *testing.T) {
					changed := spec.Copy()
					change.mutate(changed)
					if err := validateMaps(changed); err == nil {
						t.Fatal("invalid required map was not rejected")
					}
				})
			}
		})
	}
}

func TestMeasurementMode(t *testing.T) {
	for _, test := range []struct {
		typ   ebpf.MapType
		flags uint32
		want  string
	}{
		{ebpf.Hash, unix.BPF_F_NO_PREALLOC, "occupancy"},
		{ebpf.Hash, 0, "baseline"},
		{ebpf.LRUHash, 0, "baseline"},
		{ebpf.Array, 0, "baseline"},
		{ebpf.PerCPUArray, 0, "baseline"},
		{ebpf.ArrayOfMaps, 0, "baseline"},
		{ebpf.RingBuf, 0, "baseline"},
		{ebpf.LPMTrie, unix.BPF_F_NO_PREALLOC, ""},
		{ebpf.SkStorage, unix.BPF_F_NO_PREALLOC, ""},
		{ebpf.SockMap, 0, ""},
	} {
		t.Run(fmt.Sprintf("%s/%d", test.typ, test.flags), func(t *testing.T) {
			ms := &ebpf.MapSpec{Type: test.typ, Flags: test.flags}
			if got := measurementMode(ms); got != test.want {
				t.Fatalf("mode=%q, want %q", got, test.want)
			}
			if test.want == "" {
				var out bytes.Buffer
				if err := measure(&out, "unsupported", ms); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "status=not_measured") || strings.Contains(out.String(), "memlock:") {
					t.Fatalf("unsupported type was not clearly reported: %s", out.String())
				}
			}
		})
	}
}

func TestMeasureRejectsShortHashKey(t *testing.T) {
	ms := &ebpf.MapSpec{Type: ebpf.Hash, Flags: unix.BPF_F_NO_PREALLOC, KeySize: 2}
	var out bytes.Buffer
	if err := measure(&out, "short_key", ms); err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("short key was not rejected: %v", err)
	}
}

func TestMeasureMapKernel(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires root and DAE_TEST_ISOLATED=1 in isolated namespaces")
	}
	t.Run("collection", func(t *testing.T) {
		spec := &ebpf.CollectionSpec{Maps: make(map[string]*ebpf.MapSpec)}
		for _, name := range requiredMaps {
			spec.Maps[name] = &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}
		}
		spec.Maps["device_routes_map"] = &ebpf.MapSpec{
			Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1,
			InnerMap: &ebpf.MapSpec{
				Type: ebpf.Hash, KeySize: 6, ValueSize: 16, MaxEntries: 17,
				Flags: unix.BPF_F_NO_PREALLOC,
			},
		}
		spec.Maps["socket_storage"] = &ebpf.MapSpec{Type: ebpf.SkStorage}
		spec.Maps["domain_activity_events"] = &ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: uint32(os.Getpagesize())}
		var out bytes.Buffer
		if err := measureMaps(&out, spec); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"possible_cpus=", "active_timers=false",
			fmt.Sprintf("map=domain_activity_events type=RingBuf key=0 value=0 capacity_bytes=%d flags=0 mode=baseline", os.Getpagesize()),
			"map=device_routes_map type=ArrayOfMaps", "sample=created memlock:",
			"map=device_routes_map.inner type=Hash key=6 value=16 entries=17 flags=1 mode=occupancy",
			"elements=17 memlock:", "map=socket_storage type=SkStorage status=not_measured",
		} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("missing %q in output:\n%s", want, out.String())
			}
		}
	})
	for _, test := range []struct {
		name  string
		typ   ebpf.MapType
		flags uint32
		size  uint32
		want  []uint32
	}{
		{"hash-one", ebpf.Hash, unix.BPF_F_NO_PREALLOC, 1, []uint32{0, 1}},
		{"hash-small", ebpf.Hash, unix.BPF_F_NO_PREALLOC, 15, []uint32{0, 1, 15}},
		{"hash-checkpoint", ebpf.Hash, unix.BPF_F_NO_PREALLOC, 16, []uint32{0, 1, 16}},
		{"hash-between", ebpf.Hash, unix.BPF_F_NO_PREALLOC, 17, []uint32{0, 1, 16, 17}},
		{"hash-sparse", ebpf.Hash, unix.BPF_F_NO_PREALLOC, 1025, []uint32{0, 1, 16, 1024, 1025}},
		{"preallocated-hash", ebpf.Hash, 0, 17, nil},
		{"lru", ebpf.LRUHash, 0, 17, nil},
		{"array", ebpf.Array, 0, 17, nil},
		{"percpu", ebpf.PerCPUArray, 0, 17, nil},
		{"outer", ebpf.ArrayOfMaps, 0, 1, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			ms := &ebpf.MapSpec{
				Name: "memory_test", Type: test.typ, Flags: test.flags,
				KeySize: 4, ValueSize: 8, MaxEntries: test.size,
				Pinning:  ebpf.PinByName,
				Contents: []ebpf.MapKV{{Key: uint32(0), Value: uint64(1)}},
			}
			if test.typ == ebpf.Hash {
				ms.KeySize = 6
			}
			if test.typ == ebpf.ArrayOfMaps {
				ms.ValueSize = 4
				ms.InnerMap = &ebpf.MapSpec{
					Type: ebpf.Hash, KeySize: 6, ValueSize: 16, MaxEntries: 17,
					Flags: unix.BPF_F_NO_PREALLOC, Pinning: ebpf.PinByName,
				}
			}
			before := ms.Copy()
			var out bytes.Buffer
			if err := measure(&out, test.name, ms); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ms, before) {
				t.Fatal("measurement mutated the input spec")
			}
			var counts []uint32
			for line := range strings.SplitSeq(out.String(), "\n") {
				if !strings.HasPrefix(line, "elements=") {
					continue
				}
				var count uint32
				var memory uint64
				if n, err := fmt.Sscanf(line, "elements=%d memlock: %d", &count, &memory); err != nil || n != 2 || memory == 0 {
					t.Fatalf("invalid memory sample %q: %v", line, err)
				}
				counts = append(counts, count)
			}
			if !slices.Equal(counts, test.want) {
				t.Fatalf("occupancies=%v, want %v; output:\n%s", counts, test.want, out.String())
			}
			if test.want == nil {
				if strings.Count(out.String(), "sample=created memlock:") != 1 || strings.Count(out.String(), "memlock:") != 1 {
					t.Fatalf("expected one baseline sample: %s", out.String())
				}
			}
		})
	}
}
