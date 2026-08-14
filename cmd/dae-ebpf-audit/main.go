/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

const daeParamSize = 20

// daeParam must match struct dae_param in control/kern/tproxy.c.
type daeParam struct {
	ControlPlanePid      uint32
	Dae0Ifindex          uint32
	Dae0peerIfindex      uint32
	Dae0peerMac          [6]uint8
	HasBpfGetCurrentTask uint8
	Padding              uint8
}

type auditScenario struct {
	name  string
	param daeParam
}

func main() {
	var objectPath string
	var outputDir string
	var hold bool
	flag.StringVar(&objectPath, "object", "", "path to the compiled eBPF ELF object")
	flag.StringVar(&outputDir, "output-dir", "build/ebpf-audit", "directory to write audit artifacts")
	flag.BoolVar(&hold, "hold", false, "keep the collection loaded until the process receives SIGINT or SIGTERM")
	flag.Parse()

	if err := run(objectPath, outputDir, hold); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "dae-ebpf-audit: %v\n", err)
		os.Exit(1)
	}
}

func run(objectPath string, outputDir string, hold bool) error {
	if objectPath == "" {
		return fmt.Errorf("object path is required")
	}
	if outputDir == "" {
		return fmt.Errorf("output directory is required")
	}

	specDir := filepath.Join(outputDir, "spec")
	verifierDir := filepath.Join(outputDir, "verifier")
	for _, dir := range []string{outputDir, specDir, verifierDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}
	for _, m := range spec.Maps {
		if m == nil {
			continue
		}
		m.Pinning = ebpf.PinNone
		if m.InnerMap != nil {
			m.InnerMap.Pinning = ebpf.PinNone
		}
	}
	if err := writeSpecSummaries(spec, specDir); err != nil {
		return err
	}

	variable, ok := spec.Variables["PARAM"]
	if !ok {
		return fmt.Errorf("missing PARAM variable in %s", objectPath)
	}
	if err := validateDaeParam(variable); err != nil {
		return err
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	baseParam := daeParam{
		ControlPlanePid: 1,
		Dae0Ifindex:     1,
		Dae0peerIfindex: 1,
		Dae0peerMac:     [6]uint8{0x02, 0, 0, 0, 0, 1},
	}
	scenarios := []auditScenario{{name: "fallback", param: baseParam}}
	helperProbeErr := features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCurrentTask)
	if helperProbeErr == nil {
		helperParam := baseParam
		helperParam.HasBpfGetCurrentTask = 1
		scenarios = append(scenarios, auditScenario{name: "helper", param: helperParam})
	} else if !errors.Is(helperProbeErr, ebpf.ErrNotSupported) {
		return fmt.Errorf("probe bpf_get_current_task helper: %w", helperProbeErr)
	}

	var coll *ebpf.Collection
	completedScenarios := make([]string, 0, len(scenarios))
	for i, scenario := range scenarios {
		scenarioVerifierDir := filepath.Join(verifierDir, scenario.name)
		if err := os.MkdirAll(scenarioVerifierDir, 0o755); err != nil {
			return fmt.Errorf("create verifier directory for %s: %w", scenario.name, err)
		}
		loaded, err := loadCollection(spec, scenario, outputDir, scenarioVerifierDir)
		if err != nil {
			return err
		}
		if err := writeProgramVerifierLogs(loaded.Programs, scenarioVerifierDir); err != nil {
			loaded.Close()
			return err
		}
		completedScenarios = append(completedScenarios, scenario.name)
		if i < len(scenarios)-1 {
			loaded.Close()
			continue
		}
		coll = loaded
	}
	defer coll.Close()

	if err := writeLiveObjectManifest(coll, outputDir); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "scenarios.txt"), []byte(strings.Join(completedScenarios, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write scenario summary: %w", err)
	}
	activeScenario := scenarios[len(scenarios)-1].name
	if err := os.WriteFile(filepath.Join(outputDir, "active-scenario.txt"), []byte(activeScenario+"\n"), 0o644); err != nil {
		return fmt.Errorf("write active scenario: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "audit.ready"), fmt.Appendf(nil, "pid=%d\n", os.Getpid()), 0o644); err != nil {
		return fmt.Errorf("write ready marker: %w", err)
	}
	if hold {
		return waitForTermination()
	}
	return nil
}

func validateDaeParam(variable *ebpf.VariableSpec) error {
	if !variable.Constant() {
		return fmt.Errorf("PARAM must be a read-only constant")
	}
	if variable.Size() != daeParamSize || unsafe.Sizeof(daeParam{}) != daeParamSize {
		return fmt.Errorf("PARAM ABI size mismatch: object=%d loader=%d expected=%d", variable.Size(), unsafe.Sizeof(daeParam{}), daeParamSize)
	}
	variableType := variable.Type()
	if variableType == nil {
		return fmt.Errorf("PARAM BTF type information is missing")
	}
	if err := validateDaeParamQualifiers(variableType.Type); err != nil {
		return fmt.Errorf("PARAM declaration mismatch: %w", err)
	}
	if err := validateDaeParamType(variableType.Type); err != nil {
		return fmt.Errorf("PARAM ABI mismatch: %w", err)
	}
	return nil
}

func validateDaeParamQualifiers(typ btf.Type) error {
	var hasConst bool
	var hasVolatile bool
	for range 32 {
		switch qualified := typ.(type) {
		case *btf.Const:
			hasConst = true
			typ = qualified.Type
		case *btf.Volatile:
			hasVolatile = true
			typ = qualified.Type
		case *btf.Typedef:
			typ = qualified.Type
		default:
			if !hasConst || !hasVolatile {
				return fmt.Errorf("type must be volatile const, got %v", typ)
			}
			return nil
		}
	}
	return fmt.Errorf("qualifier nesting exceeds 32 levels")
}

func validateDaeParamType(typ btf.Type) error {
	strct, ok := btf.UnderlyingType(typ).(*btf.Struct)
	if !ok {
		return fmt.Errorf("type is %T, want struct dae_param", btf.UnderlyingType(typ))
	}
	if strct.Name != "dae_param" {
		return fmt.Errorf("struct name is %q, want %q", strct.Name, "dae_param")
	}
	if strct.Size != daeParamSize {
		return fmt.Errorf("struct size is %d, want %d", strct.Size, daeParamSize)
	}

	var layout daeParam
	expected := []struct {
		name       string
		offset     uintptr
		size       uint32
		arrayElems uint32
	}{
		{"control_plane_pid", unsafe.Offsetof(layout.ControlPlanePid), 4, 0},
		{"dae0_ifindex", unsafe.Offsetof(layout.Dae0Ifindex), 4, 0},
		{"dae0peer_ifindex", unsafe.Offsetof(layout.Dae0peerIfindex), 4, 0},
		{"dae0peer_mac", unsafe.Offsetof(layout.Dae0peerMac), 1, uint32(len(layout.Dae0peerMac))},
		{"has_bpf_get_current_task", unsafe.Offsetof(layout.HasBpfGetCurrentTask), 1, 0},
		{"padding", unsafe.Offsetof(layout.Padding), 1, 0},
	}
	if len(strct.Members) != len(expected) {
		return fmt.Errorf("struct has %d members, want %d", len(strct.Members), len(expected))
	}
	for i, want := range expected {
		member := strct.Members[i]
		if member.Name != want.name {
			return fmt.Errorf("member %d is %q, want %q", i, member.Name, want.name)
		}
		wantOffset := btf.Bits(want.offset * 8)
		if member.Offset != wantOffset || member.BitfieldSize != 0 {
			return fmt.Errorf("member %s has offset %d and bitfield size %d, want offset %d and no bitfield", want.name, member.Offset, member.BitfieldSize, wantOffset)
		}

		memberType := btf.UnderlyingType(member.Type)
		if want.arrayElems != 0 {
			array, ok := memberType.(*btf.Array)
			if !ok {
				return fmt.Errorf("member %s has type %T, want array", want.name, memberType)
			}
			if array.Nelems != want.arrayElems {
				return fmt.Errorf("member %s has %d elements, want %d", want.name, array.Nelems, want.arrayElems)
			}
			memberType = btf.UnderlyingType(array.Type)
		}
		integer, ok := memberType.(*btf.Int)
		if !ok || integer.Size != want.size || integer.Encoding != btf.Unsigned {
			return fmt.Errorf("member %s has type %v, want unsigned %d-byte integer", want.name, memberType, want.size)
		}
	}
	return nil
}

func loadCollection(spec *ebpf.CollectionSpec, scenario auditScenario, outputDir string, verifierDir string) (*ebpf.Collection, error) {
	scenarioSpec := spec.Copy()
	if err := scenarioSpec.RewriteConstants(map[string]interface{}{"PARAM": scenario.param}); err != nil {
		return nil, fmt.Errorf("rewrite PARAM for %s scenario: %w", scenario.name, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(scenarioSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction,
			LogSizeStart: 1 << 20,
		},
	})
	if err == nil {
		return coll, nil
	}

	message := fmt.Sprintf("scenario=%s\n%s\n", scenario.name, err)
	_ = os.WriteFile(filepath.Join(outputDir, "load-error.txt"), []byte(message), 0o644)
	var verifierError *ebpf.VerifierError
	if errors.As(err, &verifierError) {
		_ = os.WriteFile(filepath.Join(verifierDir, "load-main-bpf.log"), fmt.Appendf(nil, "%+v\n", verifierError), 0o644)
	}
	return nil, fmt.Errorf("load collection for %s scenario: %w", scenario.name, err)
}

func writeSpecSummaries(spec *ebpf.CollectionSpec, specDir string) error {
	programs := make([]string, 0, len(spec.Programs))
	for name, prog := range spec.Programs {
		if prog == nil {
			continue
		}
		programs = append(programs, fmt.Sprintf("%s\t%s\t%s", name, prog.Type, prog.SectionName))
	}
	sort.Strings(programs)
	if err := os.WriteFile(filepath.Join(specDir, "programs.tsv"), []byte(strings.Join(programs, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write program spec summary: %w", err)
	}

	maps := make([]string, 0, len(spec.Maps))
	for name, m := range spec.Maps {
		if m == nil {
			continue
		}
		maps = append(maps, fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d", name, m.Type, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags))
	}
	sort.Strings(maps)
	if err := os.WriteFile(filepath.Join(specDir, "maps.tsv"), []byte(strings.Join(maps, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write map spec summary: %w", err)
	}

	variables := make([]string, 0, len(spec.Variables))
	for name, variable := range spec.Variables {
		if variable == nil {
			continue
		}
		variables = append(variables, fmt.Sprintf("%s\tconstant=%t\tsize=%d\toffset=%d\tmap=%s", name, variable.Constant(), variable.Size(), variable.Offset(), variable.MapName()))
	}
	sort.Strings(variables)
	if err := os.WriteFile(filepath.Join(specDir, "variables.tsv"), []byte(strings.Join(variables, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write variable spec summary: %w", err)
	}
	return nil
}

func writeProgramVerifierLogs(programs map[string]*ebpf.Program, verifierDir string) error {
	for _, name := range sortedKeys(programs) {
		prog := programs[name]
		if prog == nil || prog.VerifierLog == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(verifierDir, name+".log"), []byte(prog.VerifierLog), 0o644); err != nil {
			return fmt.Errorf("write verifier log for %s: %w", name, err)
		}
	}
	return nil
}

func writeLiveObjectManifest(coll *ebpf.Collection, outputDir string) error {
	manifest := make([]string, 0, len(coll.Programs)+len(coll.Maps))
	for _, name := range sortedKeys(coll.Programs) {
		prog := coll.Programs[name]
		if prog == nil {
			continue
		}
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("inspect program %s: %w", name, err)
		}
		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("program %s id unavailable", name)
		}
		manifest = append(manifest, fmt.Sprintf("program\t%s\t%d", name, id))
	}

	for _, name := range sortedKeys(coll.Maps) {
		m := coll.Maps[name]
		if m == nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("inspect map %s: %w", name, err)
		}
		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("map %s id unavailable", name)
		}
		manifest = append(manifest, fmt.Sprintf("map\t%s\t%d", name, id))
	}

	sort.Strings(manifest)
	if err := os.WriteFile(filepath.Join(outputDir, "manifest.tsv"), []byte(strings.Join(manifest, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func waitForTermination() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	return nil
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for name := range m {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}
