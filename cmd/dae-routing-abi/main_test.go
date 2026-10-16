// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
)

func TestExtractEnums(t *testing.T) {
	generated, err := extract([]byte(`package control
import "unused"
type bpfFlags uint64
const (bpfFlagsCAPTURE_DNS bpfFlags = 8; bpfFlagsSKIPPED bpfFlags = 2199023255552)
const bpfVarFlags = "flags"
type bpfMap struct { FD int }
func loadBpf() {}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(generated)
	for _, want := range []string{"package routingabi", "CAPTURE_DNS = 8", "SKIPPED     = 2199023255552"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in generated constants:\n%s", want, s)
		}
	}
	for _, unwanted := range []string{"import", "bpfFlags", "bpfMap", "loadBpf"} {
		if strings.Contains(s, unwanted) {
			t.Fatalf("platform-specific declaration %q escaped into ABI", unwanted)
		}
	}
}

func TestExtractRejectsMissingOrChangedEnumFormat(t *testing.T) {
	for _, source := range []string{
		"package control; type bpfMap struct{}",
		"package control; const VALUE = 8",
		"package control; type bpfFlags uint8; const VALUE bpfFlags = 8",
	} {
		if _, err := extract([]byte(source)); err == nil {
			t.Fatalf("accepted unsupported source: %s", source)
		}
	}
}
