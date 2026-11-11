//go:build ignore

// SPDX-License-Identifier: AGPL-3.0-only

// Measure kernel-reported memory for map layouts in the production ELF without
// reusing pinned maps or attaching programs.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func report(out io.Writer, m *ebpf.Map, sample string) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "memlock:") {
			_, err := fmt.Fprintf(out, "%s %s\n", sample, line)
			return err
		}
	}
	return fmt.Errorf("kernel does not report map memlock in fdinfo")
}

func measurementMode(ms *ebpf.MapSpec) string {
	switch ms.Type {
	case ebpf.Hash:
		if ms.Flags&unix.BPF_F_NO_PREALLOC != 0 {
			return "occupancy"
		}
		return "baseline"
	case ebpf.LRUHash, ebpf.Array, ebpf.PerCPUArray, ebpf.ArrayOfMaps:
		return "baseline"
	default:
		return ""
	}
}

var requiredMaps = []string{
	"routing_interface_map", "routing_profile_map", "routing_map",
	"udp_bindings_map", "udp_routing_cache_map", "tcp_flow_map",
	"udp_conn_state_map", "udp_inbound_pending_map",
	"device_routes_map", "domain_routing_map",
	"redirect_track", "routing_tuples_map",
	"ingress_scratch_map",
}

func validateMaps(spec *ebpf.CollectionSpec) error {
	for _, name := range requiredMaps {
		ms := spec.Maps[name]
		if ms == nil {
			return fmt.Errorf("ELF does not contain required map %q", name)
		}
		if measurementMode(ms) == "" {
			return fmt.Errorf("required map %q has unsupported type %s", name, ms.Type)
		}
	}
	device := spec.Maps["device_routes_map"]
	if device.Type != ebpf.ArrayOfMaps || device.InnerMap == nil {
		return fmt.Errorf("device_routes_map must contain an inner map template")
	}
	if measurementMode(device.InnerMap) == "" {
		return fmt.Errorf("device_routes_map.inner has unsupported type %s", device.InnerMap.Type)
	}
	return nil
}

func measure(out io.Writer, name string, ms *ebpf.MapSpec) error {
	mode := measurementMode(ms)
	if mode == "" {
		_, err := fmt.Fprintf(out, "map=%s type=%s status=not_measured reason=%q\n",
			name, ms.Type, "requires a dedicated fixture")
		return err
	}
	if mode == "occupancy" && ms.KeySize < 4 {
		return fmt.Errorf("occupancy measurement requires a key of at least 4 bytes")
	}
	ms = ms.Copy()
	for isolated := ms; isolated != nil; isolated = isolated.InnerMap {
		isolated.Pinning = ebpf.PinNone
		// Measure only the layout, omitting ELF initial values and preset inner-map references.
		isolated.Contents = nil
	}
	m, err := ebpf.NewMap(ms)
	if err != nil {
		return err
	}
	defer m.Close()
	if _, err := fmt.Fprintf(out, "map=%s type=%s key=%d value=%d entries=%d flags=%d mode=%s\n",
		name, ms.Type, ms.KeySize, ms.ValueSize, ms.MaxEntries, ms.Flags, mode); err != nil {
		return err
	}
	if mode == "baseline" {
		return report(out, m, "sample=created")
	}
	if err := report(out, m, "elements=0"); err != nil {
		return err
	}
	key, value := make([]byte, ms.KeySize), make([]byte, ms.ValueSize)
	var count uint32
	for _, goal := range []uint32{1, 16, 1024, 65536, ms.MaxEntries} {
		if goal <= count || goal > ms.MaxEntries {
			continue
		}
		for count < goal {
			binary.NativeEndian.PutUint32(key, count)
			if err := m.Update(key, value, ebpf.UpdateNoExist); err != nil {
				return fmt.Errorf("insert element %d: %w", count, err)
			}
			count++
		}
		if err := report(out, m, fmt.Sprintf("elements=%d", count)); err != nil {
			return err
		}
	}
	return nil
}

func measureMaps(out io.Writer, spec *ebpf.CollectionSpec) error {
	if err := validateMaps(spec); err != nil {
		return err
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "scope=isolated_map_layout metric=fdinfo.memlock possible_cpus=%d active_timers=false\n", cpus); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(spec.Maps)) {
		for ms := spec.Maps[name]; ms != nil; ms = ms.InnerMap {
			if err := measure(out, name, ms); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			name += ".inner"
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: routing-map-memory <bpf ELF path>")
		os.Exit(2)
	}
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := measureMaps(os.Stdout, spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
