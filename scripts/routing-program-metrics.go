//go:build ignore

// SPDX-License-Identifier: AGPL-3.0-only

// Measure production classifier loading against isolated maps. No maps are
// pinned or reused from a daemon, and no program is attached to an interface.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
)

func measure(path string, runs int) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return err
	}
	names := []string{"lan_ingress_l2", "tproxy_wan_egress_l2"}
	for _, name := range names {
		if spec.Programs[name] == nil {
			return fmt.Errorf("ELF does not contain production classifier %q", name)
		}
	}
	for _, ms := range spec.Maps {
		for ms != nil {
			ms.Pinning = ebpf.PinNone
			ms = ms.InnerMap
		}
	}
	mapSpec := spec.Copy()
	mapSpec.Programs = nil
	maps, err := ebpf.NewCollection(mapSpec)
	if err != nil {
		return fmt.Errorf("create isolated maps: %w", err)
	}
	defer maps.Close()

	for _, name := range names {
		for run := 1; run <= runs; run++ {
			if err := measureProgram(spec, maps.Maps, name, run); err != nil {
				return fmt.Errorf("%s run %d: %w", name, run, err)
			}
		}
	}
	return nil
}

func measureProgram(spec *ebpf.CollectionSpec, maps map[string]*ebpf.Map, name string, run int) error {
	spec = spec.Copy()
	spec.Programs = map[string]*ebpf.ProgramSpec{name: spec.Programs[name]}
	// Include collection loading and map FD duplication, but exclude ELF
	// parsing, isolated map creation, metadata reads and program destruction.
	start := time.Now()
	loaded, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: maps})
	elapsed := time.Since(start)
	if err != nil {
		return err
	}
	defer loaded.Close()
	info, err := loaded.Programs[name].Info()
	if err != nil {
		return err
	}
	verified, translated, jited := "unavailable", "unavailable", "unavailable"
	if value, ok := info.VerifiedInstructions(); ok {
		verified = fmt.Sprint(value)
	}
	if value, err := info.TranslatedSize(); err == nil {
		translated = fmt.Sprint(value)
	}
	if value, err := info.JitedSize(); err == nil {
		jited = fmt.Sprint(value)
	}
	fmt.Printf("program=%s run=%d load_ms=%.3f verified_insns=%s translated_bytes=%s jit_bytes=%s\n",
		name, run, float64(elapsed)/float64(time.Millisecond), verified, translated, jited)
	return nil
}

func main() {
	runs := 5
	valid := len(os.Args) == 2 || len(os.Args) == 3
	if len(os.Args) == 3 {
		var err error
		runs, err = strconv.Atoi(os.Args[2])
		valid = err == nil && runs > 0
	}
	if !valid {
		fmt.Fprintln(os.Stderr, "usage: routing-program-metrics <BPF ELF path> [runs (default 5)]")
		os.Exit(2)
	}
	if err := measure(os.Args[1], runs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
