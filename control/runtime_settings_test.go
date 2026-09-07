// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/settings"
)

func TestRuntimeSettingsReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	group := plane.outbounds[0]
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	selected := group.Dialers[1].StatsID()
	document := fmt.Sprintf(`{"selectors":{"proxy":%q},"clients":{"gaming":["02:00:00:00:00:0a"]},"mitm":{"02:00:00:00:00:0a":true}}`, selected)
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(enabled bool) {
		t.Helper()
		wantID, wantRoute := group.DefaultSelection(), consts.OutboundDirect
		if enabled {
			wantID, wantRoute = selected, consts.OutboundUserDefinedMin
		}
		if group.Selection() != wantID {
			t.Fatalf("selection = %s, want %s", group.Selection(), wantID)
		}
		if got, _ := plane.mitmSelection(netip.MustParseAddr("192.0.2.10"), mac); got != enabled {
			t.Fatalf("MITM enabled = %v", got)
		}
		requireClientRoute(t, plane.routingMatcher, mac, 443, wantRoute)
	}
	if changed, err := plane.ReloadRuntimeSettings(); changed || err != nil {
		t.Fatal(changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reload created absent state: %v", err)
	}
	write(document)
	if changed, err := plane.ReloadRuntimeSettings(); !changed || err != nil {
		t.Fatal(changed, err)
	}
	check(true)
	if changed, err := plane.ReloadRuntimeSettings(); changed || err != nil {
		t.Fatal(changed, err)
	}
	for _, invalid := range []string{`{"selectors":`, strings.Replace(document, selected, "missing-node", 1)} {
		write(invalid)
		if changed, err := plane.ReloadRuntimeSettings(); changed || err == nil {
			t.Fatal(changed, err)
		}
		check(true)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if changed, err := plane.ReloadRuntimeSettings(); changed || err != nil {
		t.Fatal(changed, err)
	}
	check(true)
	write(`{"selectors":{},"clients":{},"mitm":{}}`)
	if changed, err := plane.ReloadRuntimeSettings(); !changed || err != nil {
		t.Fatal(changed, err)
	}
	check(false)

	// API writes have already been applied and must not trigger a second reload.
	if w := apiTestRequest(plane.apiHandler("test", testClientMAC), "PUT", "/api/device/sets/gaming", "", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if changed, err := plane.ReloadRuntimeSettings(); changed || err != nil {
		t.Fatal(changed, err)
	}
}

func TestRuntimeSettingsReloadRollsBackEarlierSelections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	plane.closeOnRouteChange, plane.deviceRoutes = true, newTestDeviceRoutes(t)
	deviceLease, err := plane.deviceRoutes.acquire(&bpfRoutingResult{Mac: [6]byte{2, 0, 0, 0, 0, 10}})
	if err != nil {
		t.Fatal(err)
	}
	plane.outbounds[0].SetConnectionPolicy(true, true)
	groupSelection, _ := plane.outbounds[0].SelectConnection(*common.NetworkUDP4.NetworkType(), true)
	other := newAPITestPlane(t, store).outbounds[0]
	other.Name = "other"
	plane.outbounds = append(plane.outbounds, other)
	data := fmt.Sprintf(`{"selectors":{"proxy":%q,"other":"missing-node"},"clients":{"gaming":["02:00:00:00:00:0a"]},"mitm":{"02:00:00:00:00:0a":true}}`, plane.outbounds[0].Dialers[1].StatsID())
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := plane.ReloadRuntimeSettings(); changed || err == nil {
		t.Fatal(changed, err)
	}
	if deviceLease.AbortCause() != nil || groupSelection.Lease.AbortCause() != nil {
		t.Fatal("rolled-back reload aborted existing connections")
	}
	for _, group := range plane.outbounds {
		if group.Selection() != group.DefaultSelection() || store.Selection(group.Name) != "" {
			t.Fatalf("failed reload changed selector %s", group.Name)
		}
	}
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	if _, exists := store.MITM(mac); exists || len(store.Members("gaming")) != 0 {
		t.Fatal("failed reload changed stored preferences")
	}
	requireClientRoute(t, plane.routingMatcher, mac, 443, consts.OutboundDirect)
	if onDisk, err := os.ReadFile(path); err != nil || string(onDisk) != data {
		t.Fatal("failed reload overwrote the edited file", err)
	}
}

func TestRuntimeSettingsReloadSerializesAPIWrites(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 20 {
			if _, err := plane.ReloadRuntimeSettings(); err != nil {
				t.Error(err)
			}
		}
	})
	for i := range 8 {
		workers.Go(func() {
			mac := [6]byte{2, 0, 0, 0, 0, byte(i)}
			handler := plane.apiHandler("test", func(netip.AddrPort, netip.AddrPort) ([6]byte, error) { return mac, nil })
			for _, method := range []string{"PUT", "DELETE", "PUT", "PUT"} {
				if w := apiTestRequest(handler, method, "/api/device/sets/gaming", "", ""); w.Code != 200 {
					t.Error(w.Code, w.Body.String())
				}
			}
		})
	}
	workers.Wait()
	if _, err := plane.ReloadRuntimeSettings(); err != nil {
		t.Fatal(err)
	}
	if len(store.Members("gaming")) != 8 {
		t.Fatal("concurrent updates lost a device membership")
	}
	for i := range 8 {
		requireClientRoute(t, plane.routingMatcher, [6]byte{2, 0, 0, 0, 0, byte(i)}, 443, consts.OutboundUserDefinedMin)
	}
}
