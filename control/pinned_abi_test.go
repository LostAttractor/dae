// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

// These expectations are independent of generated Go types: updating C and Go
// together must not silently change the format of retained kernel state.
func TestPinnedMapABI(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		kind              ebpf.MapType
		key, value, flags uint32
	}{
		"tcp_flow_map":           {ebpf.LRUHash, 40, 24, 0},
		"tcp_handshake_gate_map": {ebpf.Array, 4, 8, 0},
		"daemon_identity_map":    {ebpf.Array, 4, 8, 0},
		"fallback_sequence_map":  {ebpf.Array, 4, 8, 0},
		"cookie_pid_map":         {ebpf.SkStorage, 4, 20, unix.BPF_F_NO_PREALLOC},
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinByName {
			continue
		}
		if _, ok := want[name]; !ok {
			t.Errorf("pinned map %s needs an explicit ABI contract", name)
		}
	}
	for name, w := range want {
		m := spec.Maps[name]
		if m == nil || m.Pinning != ebpf.PinByName || m.Type != w.kind || m.KeySize != w.key || m.ValueSize != w.value || m.Flags != w.flags {
			t.Fatalf("%s: persistent map shape changed: %+v; want %+v", name, m, w)
		}
		if len(m.Contents) != 0 {
			t.Fatalf("%s: initial contents would overwrite retained entries", name)
		}
		// TCP capacity is configurable at build time; socket storage has none.
		if name == "tcp_flow_map" && m.MaxEntries == 0 || name == "cookie_pid_map" && m.MaxEntries != 0 {
			t.Fatalf("%s: invalid capacity %d", name, m.MaxEntries)
		}
	}
	type field struct {
		name         string
		offset, size int
	}
	for name, want := range map[string]struct {
		typ    btf.Type
		size   uint32
		fields []field
	}{
		"tcp_flow_map/key":     {spec.Maps["tcp_flow_map"].Key, 40, []field{{"sip", 0, 16}, {"dip", 16, 16}, {"sport", 32, 2}, {"dport", 34, 2}, {"l4proto", 36, 1}}},
		"tcp_flow_map/value":   {spec.Maps["tcp_flow_map"].Value, 24, []field{{"route_epoch", 0, 8}, {"mark", 8, 4}, {"fallback", 12, 4}, {"syn_seq", 16, 4}, {"padding", 20, 4}}},
		"cookie_pid_map/value": {spec.Maps["cookie_pid_map"].Value, 20, []field{{"pid", 0, 4}, {"pname", 4, 16}}},
	} {
		t.Run(name, func(t *testing.T) {
			layout, ok := btf.UnderlyingType(want.typ).(*btf.Struct)
			if !ok {
				t.Fatalf("persistent %s is no longer a struct: %v", name, want.typ)
			}
			if layout.Size != want.size || len(layout.Members) != len(want.fields) {
				t.Fatalf("persistent %s layout changed: %+v", name, layout)
			}
			for i, f := range want.fields {
				m := layout.Members[i]
				size, err := btf.Sizeof(m.Type)
				if err != nil || m.Name != f.name || m.Offset != btf.Bits(f.offset*8) || size != f.size || m.BitfieldSize != 0 {
					t.Fatalf("persistent field %+v changed: %+v size=%d, %v", f, m, size, err)
				}
				if integer, ok := btf.UnderlyingType(m.Type).(*btf.Int); ok && integer.Encoding != btf.Unsigned {
					t.Fatalf("persistent field %s must stay unsigned", m.Name)
				}
			}
		})
	}
	if routingabi.FALLBACK_TOKEN_RESERVED != 1 {
		t.Fatal("invalid fallback marker must remain 1; issued fallback tokens start at 2")
	}
}
