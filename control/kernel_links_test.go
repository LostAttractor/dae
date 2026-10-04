// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"testing"

	"github.com/daeuniverse/dae/component/network"
	"github.com/vishvananda/netlink"
)

func TestKernelLinksSurviveReloadAndPruneRemovedInterfaces(t *testing.T) {
	links := new(kernelLinks)
	closed := make(map[int]int)
	for _, index := range []int{1, 2} {
		links.ownHostTCXLink(hostTCXLink{linkIndex: index, role: hostTCXLanIngress,
			close: func() error { closed[index]++; return nil }})
	}
	for range 3 {
		links.beginRebind()
		if !links.useHostTCXLink(1, hostTCXLanIngress) {
			t.Fatal("reload lost existing interface attachment")
		}
		if err := links.finishRebind(); err != nil {
			t.Fatal(err)
		}
		if closed[1] != 0 || closed[2] != 1 {
			t.Fatalf("reload closed wrong attachments: %v", closed)
		}
	}
	if err := links.Close(); err != nil {
		t.Fatal(err)
	}
	if closed[1] != 1 || closed[2] != 1 {
		t.Fatalf("terminal cleanup = %v", closed)
	}
}

func TestReloadKeepsWANAttachmentsWhileDiscoveryRetries(t *testing.T) {
	for _, preparationFails := range []bool{false, true} {
		core := &controlPlaneCore{kernelLinks: new(kernelLinks), closed: t.Context(), wanBindings: make(map[int]*wanBinding)}
		closed := 0
		for _, role := range []hostTCXRole{hostTCXWanIngress, hostTCXWanEgress} {
			core.ownHostTCXLink(hostTCXLink{linkIndex: 2, role: role, close: func() error { closed++; return nil }})
		}
		core.beginRebind()
		core.seedAutoWanBindings()
		lookup := func(int) (netlink.Link, error) { return &netlink.Dummy{Index: 2, Name: "wan0"}, nil }
		retry := core.reconcileWanWith(nil, func(string) error {
			if preparationFails {
				return errors.New("temporary sysctl failure")
			}
			return nil
		}, lookup)
		if err := core.finishRebind(); err != nil || closed != 0 || retry != preparationFails {
			t.Fatalf("reload lost inherited WAN while discovery retried: closed=%d retry=%v err=%v", closed, retry, err)
		}
		core.beginRebind()
		replacement := &network.HostNetworkSnapshot{Interfaces: []network.DefaultRouteInterface{{Index: 3, Name: "new-wan", IPv4Default: true}}}
		core.reconcileWanWith(replacement, nil, func(int) (netlink.Link, error) {
			return nil, errors.New("replacement interface temporarily unavailable")
		})
		if err := core.finishRebind(); err != nil || closed != 0 {
			t.Fatalf("reload dropped the old WAN before its replacement was ready: closed=%d err=%v", closed, err)
		}
		// The eventual authoritative snapshot can remove provisional ownership.
		core.reconcileWanWith(&network.HostNetworkSnapshot{}, nil, lookup)
		if closed != 2 {
			t.Fatalf("discovery retained obsolete WAN attachments: closed=%d", closed)
		}
	}
}
