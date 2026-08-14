//go:build trace && (amd64 || arm64 || riscv64 || loong64 || ppc64 || ppc64le)

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type Symbol struct {
	Type string
	Name string
	Addr uint64
}

var kallsyms []Symbol
var kallsymsByName map[string]Symbol = make(map[string]Symbol)
var kallsymsByAddr map[uint64]Symbol = make(map[uint64]Symbol)
var kprobeSymbols = make(map[string]struct{})

func ReadKallsyms() {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		log.Fatalf("failed to open /proc/kallsyms: %v", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		typ, name := parts[1], parts[2]
		kallsyms = append(kallsyms, Symbol{typ, name, addr})
		kallsymsByName[name] = Symbol{typ, name, addr}
		kallsymsByAddr[addr] = Symbol{typ, name, addr}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("failed to read /proc/kallsyms: %v", err)
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
	readKprobeSymbols()
}

func readKprobeSymbols() {
	for _, path := range []string{
		"/sys/kernel/tracing/available_filter_functions",
		"/sys/kernel/debug/tracing/available_filter_functions",
	} {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 0 {
				kprobeSymbols[fields[0]] = struct{}{}
			}
		}
		closeErr := file.Close()
		if err := scanner.Err(); err != nil {
			log.Debugf("failed to read %s: %v", path, err)
			continue
		}
		if closeErr != nil {
			log.Debugf("failed to close %s: %v", path, closeErr)
		}
		return
	}
}

func NearestSymbol(addr uint64) Symbol {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int { return int(x.Addr - addr) })
	if idx == len(kallsyms) {
		return kallsyms[idx-1]
	}
	if kallsyms[idx].Addr == addr {
		return kallsyms[idx]
	}
	if idx == 0 {
		return kallsyms[0]
	}
	return kallsyms[idx-1]
}
