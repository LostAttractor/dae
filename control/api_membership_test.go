// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/settings"
)

func TestMembershipRejectsInvalidRequestsBeforeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	for _, managed := range []bool{false, true} {
		for _, joined := range []bool{false, true} {
			for _, request := range []struct {
				name string
				mac  [6]byte
			}{
				{"gaming", [6]byte{}},
				{"gaming", [6]byte{1, 0, 0, 0, 0, 1}},
				{"gaming", [6]byte{255, 255, 255, 255, 255, 255}},
				{"absent", [6]byte{2, 0, 0, 0, 0, 1}},
			} {
				if managed {
					_, err = plane.UpdateManagedMembership(request.name, request.mac, joined)
				} else {
					_, err = plane.UpdateClientSet(request.name, netip.Addr{}, request.mac, joined)
				}
				if err == nil {
					t.Errorf("accepted managed=%t joined=%t request=%+v", managed, joined, request)
				}
			}
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid request wrote settings: %v", err)
	}
	if len(store.Members("gaming")) != 0 || len(store.Members("absent")) != 0 {
		t.Fatal("invalid request changed membership")
	}
}

func TestManagedMembershipReturnsCommittedSnapshot(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	text := net.HardwareAddr(mac[:]).String()
	var workers sync.WaitGroup
	start := make(chan struct{})
	for worker := range 4 {
		workers.Go(func() {
			<-start
			for round := range 30 {
				joined := (worker+round)%2 == 0
				group, err := plane.UpdateManagedMembership("gaming", mac, joined)
				if err != nil {
					t.Error(err)
					return
				}
				if slices.Contains(group.Members, text) != joined {
					t.Errorf("joined=%t returned a different transaction's members: %v", joined, group.Members)
				}
			}
		})
	}
	close(start)
	workers.Wait()
	want := consts.OutboundDirect
	if slices.Contains(store.Members("gaming"), mac) {
		want = consts.OutboundUserDefinedMin
	}
	requireClientRoute(t, plane.routingMatcher, mac, 443, want)
}
