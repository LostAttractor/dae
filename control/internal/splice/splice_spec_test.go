//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import "testing"

func TestSpliceMapShape(t *testing.T) {
	spec, err := loadBpf_splice()
	if err != nil {
		t.Fatal(err)
	}
	const maxEndpoints = 65536 * 2
	for name, wantSize := range map[string]uint32{
		"splice_socks":     8,
		"splice_endpoints": 16,
		"splice_stats":     40,
	} {
		m := spec.Maps[name]
		if m == nil {
			t.Fatalf("%s is missing", name)
		}
		if m.ValueSize != wantSize || m.MaxEntries != maxEndpoints {
			t.Fatalf("%s shape = value:%d max:%d, want value:%d max:%d",
				name, m.ValueSize, m.MaxEntries, wantSize, maxEndpoints)
		}
	}
}
