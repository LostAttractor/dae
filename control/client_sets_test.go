// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

func TestClientExportAPIAndReload(t *testing.T) {
	if os.Getenv("DAE_TEST_NETFILTER") != "1" {
		t.Skip("requires an isolated network namespace with CAP_NET_ADMIN")
	}
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	plane.clients = map[string]config.Client{
		"external": {Description: "Firewall devices", NFTSet: "inet/dae_api_test/devices"},
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "dae_api_test"}
	conn := &nftables.Conn{}
	t.Cleanup(func() { conn.DelTable(table); _ = conn.Flush() })
	mac, _ := testClientMAC(netip.AddrPort{}, netip.AddrPort{})
	if err := store.SetMembers("external", [][6]byte{mac}); err != nil {
		t.Fatal(err)
	}
	if err := plane.restoreRuntimeSettings(false); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.GetSetByName(table, "devices"); err == nil {
		t.Fatal("candidate preparation modified netfilter")
	}
	if err := plane.syncClientExports(); err != nil {
		t.Fatal(err)
	}
	plane.kernelReady = true
	handler := plane.apiHandler("test", testClientMAC, nil)
	check := func(want [][6]byte) {
		t.Helper()
		set, err := conn.GetSetByName(table, "devices")
		if err != nil {
			t.Fatal(err)
		}
		elements, err := conn.GetSetElements(set)
		if err != nil {
			t.Fatal(err)
		}
		var got [][6]byte
		for _, element := range elements {
			got = append(got, [6]byte(element.Key))
		}
		if !slices.Equal(got, want) || !slices.Equal(store.Members("external"), want) {
			t.Fatalf("members: kernel=%x stored=%x want=%x", got, store.Members("external"), want)
		}
	}
	check([][6]byte{mac})
	if w := apiTestRequest(handler, "DELETE", "/api/device/sets/external", "", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	check(nil)
	if w := apiTestRequest(handler, "PUT", "/api/device/sets/external", "", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	check([][6]byte{mac})
	// A state-file edit follows the same publication path as the API.
	if err := os.WriteFile(path, []byte(`{"selectors":{},"clients":{},"mitm":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := plane.ReloadRuntimeSettings(); !changed || err != nil {
		t.Fatal(changed, err)
	}
	check(nil)
	// Persisting fails after the kernel update: restore kernel and store together.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if w := apiTestRequest(handler, "PUT", "/api/device/sets/external", "", ""); w.Code != 500 {
		t.Fatal(w.Code, w.Body.String())
	}
	check(nil)
}

func TestClientExportFailureRestoresAllMembers(t *testing.T) {
	if os.Getenv("DAE_TEST_NETFILTER") != "1" {
		t.Skip("requires an isolated network namespace with CAP_NET_ADMIN")
	}
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	outer := attachClientKernelMaps(t, plane.routingMatcherBuilder)
	plane.clients = map[string]config.Client{
		"gaming":    {IPSet: "dae_rollback", NFTSet: "inet/dae_rollback/gaming"},
		"streaming": {NFTSet: "inet/dae_rollback/streaming"},
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "dae_rollback"}
	conn := &nftables.Conn{}
	t.Cleanup(func() {
		_ = netlink.IpsetDestroy("dae_rollback")
		conn.DelTable(table)
		_ = conn.Flush()
	})
	mac, _ := testClientMAC(netip.AddrPort{}, netip.AddrPort{})
	previous := [6]byte{2, 0, 0, 0, 0, 1}
	if err := store.SetMembers("gaming", [][6]byte{previous}); err != nil {
		t.Fatal(err)
	}
	if err := plane.syncClientExports(); err != nil {
		t.Fatal(err)
	}
	for _, name := range plane.routingMatcherBuilder.ClientSets() {
		if err := plane.routingMatcherBuilder.SetClientMembers(plane.routingMatcher, name, store.Members(name), true); err != nil {
			t.Fatal(err)
		}
	}
	plane.kernelReady = true

	check := func() {
		t.Helper()
		if !slices.Equal(store.Members("gaming"), [][6]byte{previous}) || len(store.Members("streaming")) != 0 {
			t.Fatal("failed update changed accepted members")
		}
		requireClientRoute(t, plane.routingMatcher, previous, 443, consts.OutboundUserDefinedMin)
		requireClientRoute(t, plane.routingMatcher, mac, 443, consts.OutboundDirect)
		var inner *ebpf.Map
		if err := outer.Lookup(uint32(plane.routingMatcherBuilder.clientSetSlots["gaming"]), &inner); err != nil {
			t.Fatal(err)
		}
		defer inner.Close()
		for _, address := range [][6]byte{previous, mac} {
			var value uint32
			key := cidrToBpfLpmKey(sourceMacPrefixes([][6]byte{address})[0])
			err := inner.Lookup(key, &value)
			if address == previous && (err != nil || value != 1) || address == mac && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("failed update changed BPF membership for %x: %d, %v", address, value, err)
			}
		}
		ipset, err := netlink.IpsetList("dae_rollback")
		if err != nil || len(ipset.Entries) != 1 || [6]byte(ipset.Entries[0].MAC) != previous {
			t.Fatalf("failed update changed ipset: %+v, %v", ipset, err)
		}
		set, err := conn.GetSetByName(table, "gaming")
		if err != nil {
			t.Fatal(err)
		}
		elements, err := conn.GetSetElements(set)
		if err != nil || len(elements) != 1 || [6]byte(elements[0].Key) != previous {
			t.Fatalf("failed update changed nftset: %+v, %v", elements, err)
		}
	}
	check()
	// Fail the second set after a selector and the first set were updated.
	streaming, err := conn.GetSetByName(table, "streaming")
	if err != nil {
		t.Fatal(err)
	}
	conn.DelSet(streaming)
	if err := conn.AddSet(&nftables.Set{Table: table, Name: "streaming", KeyType: nftables.TypeIPAddr}, nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	group := plane.outbounds[0]
	document := fmt.Sprintf(`{"selectors":{"proxy":%q},"clients":{"gaming":["02:00:00:00:00:0a"],"streaming":["02:00:00:00:00:0a"]},"mitm":{}}`, group.Dialers[1].StatsID())
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := plane.ReloadRuntimeSettings(); changed || err == nil {
		t.Fatal("reload with an incompatible nft set succeeded", changed, err)
	}
	check()
	if group.Selection() != group.DefaultSelection() || store.Selection("proxy") != "" {
		t.Fatal("failed reload changed the selector")
	}
	// Fail persistence after all three membership targets accepted a change.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if w := apiTestRequest(plane.apiHandler("test", testClientMAC, nil), "PUT", "/api/device/sets/gaming", "", ""); w.Code != 500 {
		t.Fatal(w.Code, w.Body.String())
	}
	check()
}
