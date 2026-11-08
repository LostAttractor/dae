// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
	if err := links.Close(false); err != nil {
		t.Fatal(err)
	}
	if closed[1] != 1 || closed[2] != 1 {
		t.Fatalf("terminal cleanup = %v", closed)
	}
}

func TestReloadKeepsWANAttachmentsWhileDiscoveryRetries(t *testing.T) {
	for _, preparationFails := range []bool{false, true} {
		core := &hostBinder{kernelLinks: new(kernelLinks), closed: t.Context(), wanBindings: make(map[int]*wanBinding)}
		closed := 0
		for _, role := range []hostTCXRole{hostTCXWanIngress, hostTCXWanEgress} {
			core.ownHostTCXLink(hostTCXLink{linkIndex: 2, role: role, program: new(ebpf.Program), close: func() error { closed++; return nil }})
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

type persistentTestLink struct {
	link.Link
	closed, unpinned int
}

func (l *persistentTestLink) Close() error { l.closed++; return nil }
func (l *persistentTestLink) Unpin() error { l.unpinned++; return nil }

func TestKernelCloseReleasesPersistentAttachments(t *testing.T) {
	host, internal, pid, exit := new(persistentTestLink), new(persistentTestLink), new(persistentTestLink), new(persistentTestLink)
	links := &kernelLinks{pinPath: t.TempDir(), netnsLinks: []link.Link{internal}, pidLinks: []link.Link{pid}, exitLink: exit}
	links.ownHostTCXLink(hostTCXLink{linkIndex: 1, role: hostTCXLanIngress, link: host,
		close: host.Close})
	if err := links.Close(false); err != nil {
		t.Fatal(err)
	}
	if host.closed != 1 || internal.closed != 1 || pid.closed != 1 || exit.closed != 1 {
		t.Fatal("Close did not release every userspace descriptor")
	}
	if host.unpinned != 0 || pid.unpinned != 0 || internal.unpinned != 0 {
		t.Fatalf("host unpins=%d pid unpins=%d netns unpins=%d", host.unpinned, pid.unpinned, internal.unpinned)
	}
	if err := links.Close(false); err != nil || host.closed != 1 || pid.closed != 1 {
		t.Fatalf("Close was not idempotent: %v", err)
	}
}

func TestKernelLinksDetachHostTCX(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		for _, rebind := range []bool{false, true} {
			host := new(persistentTestLink)
			links := new(kernelLinks)
			if pinned {
				links.pinPath = t.TempDir()
			}
			links.ownHostTCXLink(hostTCXLink{linkIndex: 1, role: hostTCXLanIngress, link: host, close: host.Close})
			var err error
			if rebind {
				links.beginRebind()
				err = links.finishRebind()
			} else {
				err = links.closeHostTCXLinks(1)
			}
			if err != nil || host.closed != 1 || (host.unpinned == 1) != pinned || len(links.hostTCXLinks) != 0 {
				t.Fatalf("pinned=%v rebind=%v: closes=%d unpins=%d err=%v", pinned, rebind, host.closed, host.unpinned, err)
			}
		}
	}
}
