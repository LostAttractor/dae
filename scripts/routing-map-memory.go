//go:build ignore

// SPDX-License-Identifier: AGPL-3.0-only

// Measure kernel-reported map memory at different occupancies. This creates
// isolated maps from the supplied ELF, without pins or attached programs.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
)

func report(m *ebpf.Map, count int) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "memlock:") {
			fmt.Printf("elements=%d %s\n", count, line)
			return nil
		}
	}
	return fmt.Errorf("kernel does not report map memlock in fdinfo")
}

func measure(ms *ebpf.MapSpec) error {
	ms.Pinning = ebpf.PinNone
	m, err := ebpf.NewMap(ms)
	if err != nil {
		return err
	}
	defer m.Close()
	fmt.Printf("%s key=%d value=%d entries=%d flags=%d\n", ms.Name, ms.KeySize, ms.ValueSize, ms.MaxEntries, ms.Flags)
	if err := report(m, 0); err != nil {
		return err
	}
	if ms.Type != ebpf.Hash {
		return nil
	}
	checkpoints := []int{1, 16, int(ms.MaxEntries)}
	if ms.Name == "udp_bindings_map" || ms.Name == "udp_routing_cache_map" {
		checkpoints = []int{1, 1024, 65536, int(ms.MaxEntries)}
	}
	key, value := make([]byte, ms.KeySize), make([]byte, ms.ValueSize)
	count := 0
	for _, goal := range checkpoints {
		if goal <= count || goal > int(ms.MaxEntries) {
			continue
		}
		for count < goal {
			binary.NativeEndian.PutUint32(key, uint32(count))
			if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
				return err
			}
			count++
		}
		if err := report(m, count); err != nil {
			return err
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
	for _, name := range []string{"routing_interface_map", "routing_profile_map", "routing_map", "udp_bindings_map", "udp_routing_cache_map"} {
		ms := spec.Maps[name]
		if ms == nil {
			continue
		}
		if err := measure(ms); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			os.Exit(1)
		}
	}
}
