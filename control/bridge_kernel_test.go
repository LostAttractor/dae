// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/daeuniverse/dae/common/consts"
)

// Exercise optional CO-RE relocations even on a host with bridge netfilter.
// Only the loader's BTF copy is changed; kernel types and host links are untouched.
func TestBridgeMetadataOptionalKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF verifier tests")
	}
	for _, missing := range []struct{ typ, field string }{
		{"skb_ext_id", "SKB_EXT_BRIDGE_NF"},
		{"sk_buff", "active_extensions"},
		{"sk_buff", "extensions"},
		{"skb_ext", "offset"},
		{"nf_bridge_info", "physinif"},
	} {
		t.Run(missing.typ+"/"+missing.field, func(t *testing.T) {
			kernel, err := btf.LoadKernelSpec()
			if err != nil {
				t.Fatal(err)
			}
			kernel = kernel.Copy()
			typ, err := kernel.AnyTypeByName(missing.typ)
			if errors.Is(err, btf.ErrNotFound) {
				t.Skip("kernel already lacks " + missing.typ)
			}
			if err != nil {
				t.Fatal(err)
			}
			changed := false
			switch typ := typ.(type) {
			case *btf.Enum:
				for i := range typ.Values {
					if typ.Values[i].Name == missing.field {
						typ.Values[i].Name = "unavailable_bridge_extension"
						changed = true
					}
				}
			case *btf.Struct:
				for i := range typ.Members {
					if typ.Members[i].Name == missing.field {
						typ.Members[i].Name = "unavailable_bridge_field"
						changed = true
					}
				}
			}
			if !changed {
				t.Skip("kernel already lacks " + missing.field)
			}
			spec, err := loadBpf()
			if err != nil {
				t.Fatal(err)
			}
			for name := range spec.Programs {
				if name != "lan_ingress_l2" {
					delete(spec.Programs, name)
				}
			}
			for _, m := range spec.Maps {
				m.Pinning = ebpf.PinNone
			}
			collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernel}})
			if err != nil {
				t.Fatal(err)
			}
			defer collection.Close()
			for i, rule := range []bpfMatchSet{
				{Type: uint8(consts.MatchType_IfIndex), Outbound: uint8(consts.OutboundBlock)},
				{Type: uint8(consts.MatchType_Fallback)},
			} {
				if err := collection.Maps["routing_map"].Update(uint32(i), rule, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			profile := bpfRoutingProfile{Length: 2}
			profile.Steps[1] = 1
			if err := collection.Maps["routing_profile_map"].Update(uint32(0), profile, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.0.2.2:40001"), netip.MustParseAddrPort("10.0.0.1:22"), consts.L4ProtoType_TCP)
			status, err := collection.Programs["lan_ingress_l2"].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
			if err != nil || status != ^uint32(0) {
				t.Fatalf("missing metadata matched an unresolved interface: verdict=%d err=%v", status, err)
			}
		})
	}
}
