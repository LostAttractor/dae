// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestCreateDaeLinkPairFallback(t *testing.T) {
	for _, test := range []struct {
		name         string
		netkit, veth error
		wantCalls    []string
		wantError    bool
	}{
		{"prefer Netkit", nil, nil, []string{"netkit"}, false},
		{"missing Netkit", unix.EOPNOTSUPP, nil, []string{"netkit", "veth"}, false},
		{"missing device", unix.ENODEV, nil, []string{"netkit", "veth"}, false},
		{"no permissions", unix.EPERM, nil, []string{"netkit"}, true},
		{"name conflict", unix.EEXIST, nil, []string{"netkit"}, true},
		{"invalid parameters", unix.EINVAL, nil, []string{"netkit"}, true},
		{"out of memory", unix.ENOMEM, nil, []string{"netkit"}, true},
		{"neither device", unix.EOPNOTSUPP, unix.ENODEV, []string{"netkit", "veth"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			err := createDaeLinkPair("host", "peer", func(device netlink.Link) error {
				calls = append(calls, device.Type())
				if device.Attrs().Name != "host" {
					t.Fatalf("unexpected device name %s", device.Attrs().Name)
				}
				if device.Type() == "netkit" {
					if test.netkit != nil {
						return fmt.Errorf("netlink: %w", test.netkit)
					}
					return nil
				}
				if device.(*netlink.Veth).PeerName != "peer" {
					t.Fatal("fallback changed the peer name")
				}
				return test.veth
			})
			if !slices.Equal(calls, test.wantCalls) {
				t.Fatalf("attempted %v, want %v", calls, test.wantCalls)
			}
			if test.wantError {
				if err == nil || !errors.Is(err, test.netkit) || test.veth != nil && !errors.Is(err, test.veth) {
					t.Fatalf("lost device creation failure: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVethAttachmentFailureCleanupIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated attachment tests")
	}
	skLookup := newTestProgram(t, ebpf.SkLookup, ebpf.AttachSkLookup, 1)
	peerIngress := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXIngress, 0)
	err := withKernelProbeNamespace(func(device netlink.Link) error {
		if device.Type() == "netkit" {
			return unix.EOPNOTSUPP
		}
		return netlink.LinkAdd(device)
	}, func(ns *DaeNetns) error {
		// Fail after SK_LOOKUP and peer ingress have already been attached.
		links, err := ns.attachPrograms(bpfPrograms{
			TproxySkLookup: skLookup, TproxyDae0peerIngress: peerIngress, TproxyDae0Ingress: skLookup,
		})
		if err == nil || len(links) != 0 {
			closeBpfLinks(links)
			return fmt.Errorf("failed attachment retained ownership: links=%v err=%v", links, err)
		}
		for _, query := range []link.QueryOptions{
			{Target: int(ns.daeNs), Attach: ebpf.AttachSkLookup},
			{Target: ns.dae0peer.Attrs().Index, Attach: ebpf.AttachTCXIngress},
			{Target: ns.dae0.Attrs().Index, Attach: ebpf.AttachTCXIngress},
		} {
			result, err := link.QueryPrograms(query)
			if err != nil {
				return err
			}
			if len(result.Programs) != 0 {
				return fmt.Errorf("leaked %s programs: %+v", query.Attach, result.Programs)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
