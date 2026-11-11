// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/component/clientset"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

// Run alone with private PID, mount and network namespaces, /run and bpffs.
func TestReplacementCommitExportsFailureKernel(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires root in isolated PID, mount and network namespaces")
	}
	for _, mode := range []string{"prepare", "partial-apply", "after-apply"} {
		t.Run(mode, func(t *testing.T) {
			const ipset = "dae_replace_commit"
			const nftset = "inet/dae_replace_commit/fixture"
			old, next := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
			conn := &nftables.Conn{}
			table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "dae_replace_commit"}
			t.Cleanup(func() { _ = netlink.IpsetDestroy(ipset); conn.DelTable(table); _ = conn.Flush() })
			if err := clientset.Replace(ipset, nftset, [][6]byte{old}); err != nil {
				t.Fatal(err)
			}
			store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
			if err != nil {
				t.Fatal(err)
			}
			clients := map[string]config.Client{"fixture": {IPSet: ipset, NFTSet: nftset}}
			if mode == "prepare" || mode == "partial-apply" {
				limited := &nftables.Set{Table: table, Name: "limited", KeyType: nftables.TypeEtherAddr, Size: 1}
				key := old[:]
				if mode == "prepare" {
					limited.KeyType = nftables.TypeIPAddr
					key = []byte{192, 0, 2, 1}
				}
				if err := conn.AddSet(limited, []nftables.SetElement{{Key: key}}); err != nil {
					t.Fatal(err)
				}
				if err := conn.Flush(); err != nil {
					t.Fatal(err)
				}
				clients["limited"] = config.Client{NFTSet: "inet/dae_replace_commit/limited"}
			}
			if err := store.Update(func(snapshot *settings.Snapshot) error {
				snapshot.Clients["fixture"] = []string{"02:00:00:00:00:02"}
				if mode == "prepare" || mode == "partial-apply" {
					snapshot.Clients["limited"] = []string{"02:00:00:00:00:01", "02:00:00:00:00:02"}
				}
				return nil
			}, nil); err != nil {
				t.Fatal(err)
			}
			plane, _ := newReplacementRegistryPlane(t, "")
			plane.settings, plane.clients = store, clients
			// Fail Host.Start only after real ipset/nft publication has completed.
			plane.ctx, plane.cancel = context.WithCancel(t.Context())
			plane.cancel()
			plane.mitmHost = new(mitm.Host)
			runtime := NewRuntime()
			plane.core.bpf.Runtime = runtime
			runtime.current = plane
			runtime.staged, runtime.kernelLinks.privatePins, runtime.kernelLinks.preparing = true, true, true
			state, err := ebpf.NewMap(&ebpf.MapSpec{Name: "exited_map", Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = state.Close() })
			runtime.shared["exited_map"] = state
			if err := runtime.StopIngress(); err != nil {
				t.Fatal(err)
			}
			loadProgram := func() *ebpf.Program {
				t.Helper()
				program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
					Type: ebpf.SchedCLS, License: "GPL",
					Instructions: asm.Instructions{asm.LoadMapPtr(asm.R1, state.FD()), asm.Mov.Imm(asm.R0, 2), asm.Return()},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = program.Close() })
				return program
			}
			program, replacement := loadProgram(), loadProgram()
			device := &netlink.Dummy{Name: "replace-export"}
			if err := netlink.LinkAdd(device); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = netlink.LinkDel(device) })
			plane.lanInterface = []string{device.Name}
			var guardID link.ID
			for _, role := range []hostTCXRole{hostTCXLanIngress, hostTCXLanEgress} {
				guard, err := link.AttachTCX(link.TCXOptions{Interface: device.Index, Attach: role.attachType(), Program: program})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = guard.Close() })
				info, err := guard.Info()
				if err != nil {
					t.Fatal(err)
				}
				if role.interceptsTraffic() {
					guardID = info.ID
					if _, err := pinReplacementGuard(guard, role); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = removeReplacementGuard(replacementGuardDirectory(info.ID)) })
				}
				owned, err := link.NewFromID(info.ID)
				if err != nil {
					t.Fatal(err)
				}
				runtime.replacementDescriptors = append(runtime.replacementDescriptors, ReplacementLink{Kind: "host", Ifindex: device.Index, Role: uint8(role), Ethernet: true, ID: uint32(info.ID)})
				runtime.replacementLinks = append(runtime.replacementLinks, replacementAttachment{link: owned, next: replacement})
				runtime.kernelLinks.hostTCXLinks = append(runtime.kernelLinks.hostTCXLinks, hostTCXLink{linkIndex: device.Index, role: role, link: owned, close: owned.Close, program: replacement})
			}
			t.Cleanup(func() {
				var guards []link.ID
				for _, owned := range runtime.kernelLinks.hostTCXLinks {
					if info, err := owned.link.Info(); err == nil && owned.role.interceptsTraffic() {
						guards = append(guards, info.ID)
					}
				}
				_ = runtime.Close()
				for _, id := range guards {
					_ = removeReplacementGuard(replacementGuardDirectory(id))
				}
			})
			err = runtime.CommitReplacement(t.Context())
			if mode == "prepare" {
				if err == nil || !strings.Contains(err.Error(), "prepare replacement client exports") {
					t.Fatalf("expected export preparation failure: %v", err)
				}
				if len(runtime.replacementLinks) != len(runtime.replacementDescriptors) {
					t.Fatal("export preparation failure consumed pending attachments")
				}
				for i, owned := range runtime.kernelLinks.hostTCXLinks {
					info, err := owned.link.Info()
					if err != nil || uint32(info.ID) != runtime.replacementDescriptors[i].ID {
						t.Fatalf("export preparation failure replaced an old attachment: %v", err)
					}
				}
				guards, err := os.ReadDir(replacementGuardPath())
				if err != nil || len(guards) != 1 {
					t.Fatalf("export preparation failure installed guards: %v %v", guards, err)
				}
			} else if mode == "partial-apply" {
				if err == nil || !strings.Contains(err.Error(), "publish replacement client exports") {
					t.Fatalf("expected nft capacity failure before Host.Start: %v", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("commit did not reach Host.Start after applying exports: %v", err)
			}
			sets, err := netlink.IpsetListAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(sets) != 1 || sets[0].SetName != ipset {
				t.Fatalf("failed commit left export backups: %+v", sets)
			}
			want := next
			if mode == "prepare" {
				want = old
			}
			if len(sets[0].Entries) != 1 || !slices.Equal(sets[0].Entries[0].MAC, want[:]) {
				t.Fatalf("failed commit changed the wrong ipset state: %+v", sets[0].Entries)
			}
			requireNFT := func(name string, want [6]byte) {
				t.Helper()
				set, err := conn.GetSetByName(table, name)
				if err != nil {
					t.Fatal(err)
				}
				members, err := conn.GetSetElements(set)
				if err != nil || len(members) != 1 || !slices.Equal(members[0].Key, want[:]) {
					t.Fatalf("nftset %s members = %v, %v; want %v", name, members, err, want)
				}
			}
			if mode == "partial-apply" {
				// The nft batch is atomic, but the preceding ipset swap is not reverted.
				requireNFT("fixture", old)
				requireNFT("limited", old)
			} else {
				requireNFT("fixture", want)
			}
			if !runtime.staged || !runtime.kernelLinks.privatePins || !runtime.kernelLinks.preparing {
				t.Fatal("failed commit released replacement staging")
			}
			var status uint8
			if err := state.Lookup(uint32(0), &status); err != nil || status != uint8(routingabi.DAEMON_STOPPING) {
				t.Fatalf("failed commit released the stopping barrier: state=%d err=%v", status, err)
			}
			pinned, err := link.LoadPinnedLink(filepath.Join(replacementGuardDirectory(guardID), "link"), nil)
			if err != nil {
				t.Fatalf("failed commit removed the replacement guard: %v", err)
			}
			defer pinned.Close()
			pinnedInfo, err := pinned.Info()
			if err != nil || pinnedInfo.ID != guardID {
				t.Fatalf("failed commit changed the replacement guard: %v, %v", pinnedInfo, err)
			}
		})
	}
}
