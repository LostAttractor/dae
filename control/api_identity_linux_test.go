// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Exercise the actual LAN classifier and API resolver against isolated kernel
// routes/neighbors. No daemon maps or host interfaces are used.
func TestAPIClientIdentityIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated network namespaces and BPF")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	isolated, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer isolated.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatalf("restore network namespace: %v", err)
		}
	}()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	addLink := func(link netlink.Link) netlink.Link {
		t.Helper()
		must(netlink.LinkAdd(link))
		return link
	}
	physical := addLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "physical"}})
	lan := addLink(&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "lan", ParentIndex: physical.Attrs().Index}, VlanId: 10})
	bridge := addLink(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-lan"}})
	must(netlink.LinkSetMaster(lan, bridge))
	bond := netlink.NewLinkBond(netlink.LinkAttrs{Name: "bond0"})
	bond.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
	addLink(bond)
	bondPort := addLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "bond-port"}})
	must(netlink.LinkSetMaster(bondPort, bond))
	wan := addLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "wan"}})
	for _, link := range []netlink.Link{physical, lan, bridge, bond, bondPort, wan} {
		must(netlink.LinkSetUp(link))
	}
	address := func(link netlink.Link, cidr string) {
		t.Helper()
		addr, err := netlink.ParseAddr(cidr)
		must(err)
		addr.Flags = unix.IFA_F_NODAD
		must(netlink.AddrAdd(link, addr))
	}
	address(bridge, "192.0.2.1/24")
	address(bridge, "2001:db8::1/64")
	address(bridge, "fe80::1/64")
	address(bond, "198.51.100.1/24")
	address(wan, "203.0.113.1/24")
	address(wan, "fe80::1/64")
	mac := [6]byte{2, 0, 0, 0, 0, 23}
	other := [6]byte{2, 0, 0, 0, 0, 24}
	neighbor := func(link netlink.Link, ip string, hardware [6]byte) {
		t.Helper()
		must(netlink.NeighSet(&netlink.Neigh{LinkIndex: link.Attrs().Index, IP: net.ParseIP(ip), HardwareAddr: net.HardwareAddr(hardware[:]), State: netlink.NUD_PERMANENT}))
	}
	neighbor(bridge, "192.0.2.23", mac)
	neighbor(bridge, "2001:db8::23", mac)
	neighbor(bridge, "fe80::23", mac)
	neighbor(bond, "198.51.100.23", mac)
	neighbor(wan, "203.0.113.23", mac)
	neighbor(wan, "fe80::23", other)
	_, routed, err := net.ParseCIDR("10.0.0.0/24")
	must(err)
	must(netlink.RouteAdd(&netlink.Route{Dst: routed, Gw: net.ParseIP("192.0.2.23"), LinkIndex: bridge.Attrs().Index}))

	spec, err := loadBpf()
	must(err)
	for name := range spec.Programs {
		if name != "lan_ingress_l2" && name != "tproxy_wan_ingress_l2" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	collection, err := ebpf.NewCollection(spec)
	must(err)
	defer collection.Close()
	must(collection.Maps["routing_map"].Update(uint32(0), &bpfMatchSet{Type: uint8(consts.MatchType_Fallback)}, ebpf.UpdateAny))
	plane := &ControlPlane{
		apiPort: 9080, lanInterface: []string{"lan", "bond-port"},
		core: &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{
			bpfMaps:      bpfMaps{ApiClientMap: collection.Maps["api_client_map"]},
			bpfVariables: bpfVariables{ApiPort: collection.Variables["api_port"]},
		}}},
	}
	observe := func(source, destination netip.AddrPort, ingress netlink.Link, hardware [6]byte, lanHook bool) {
		t.Helper()
		packet := apiIdentityPacket(source, destination, hardware)
		ctx := make([]byte, 256)
		binary.NativeEndian.PutUint32(ctx[36:40], uint32(ingress.Attrs().Index))
		binary.NativeEndian.PutUint32(ctx[40:44], uint32(ingress.Attrs().Index))
		program := "tproxy_wan_ingress_l2"
		if lanHook {
			program = "lan_ingress_l2"
		}
		status, err := collection.Programs[program].Run(&ebpf.RunOptions{Data: packet, Context: ctx, Repeat: 1})
		must(err)
		if status != ^uint32(0) {
			t.Fatalf("API packet left kernel direct: verdict %d", status)
		}
	}
	handler := plane.APIHandler("identity-test", nil)
	checkKeylessAdmin := func(source, destination netip.AddrPort, allowed bool) {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), "GET", "http://192.0.2.1:9080/api/selectors", nil)
		r.Host, r.RemoteAddr = destination.String(), source.String()
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.TCPAddrFromAddrPort(destination)))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if allowed {
			var data api.SelectorsResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || !data.AdminEnabled || data.AuthMode != "lan" {
				t.Fatalf("keyless LAN administration: %d %s", w.Code, w.Body.String())
			}
		} else if w.Code != 403 {
			t.Fatalf("keyless non-LAN administration: %d %s", w.Code, w.Body.String())
		}
	}
	for _, test := range []struct {
		name, source, destination string
		ingress                   netlink.Link
		hardware                  [6]byte
		lanHook, want             bool
	}{
		{"VLAN bridge IPv4", "192.0.2.23:40001", "192.0.2.1:9080", lan, mac, true, true},
		{"VLAN bridge IPv6", "[2001:db8::23]:40001", "[2001:db8::1]:9080", lan, mac, true, true},
		{"IPv6 link local scope", "[fe80::23%br-lan]:40001", "[fe80::1%br-lan]:9080", lan, mac, true, true},
		{"bond port", "198.51.100.23:40001", "198.51.100.1:9080", bondPort, mac, true, true},
		{"WAN neighbor", "203.0.113.23:40001", "203.0.113.1:9080", wan, mac, false, false},
		{"routed peer behind LAN router", "10.0.0.23:40001", "192.0.2.1:9080", lan, mac, true, false},
		{"neighbor MAC mismatch", "192.0.2.23:40001", "192.0.2.1:9080", lan, other, true, false},
		{"router address", "192.0.2.1:40001", "192.0.2.1:9080", lan, mac, true, false},
		{"IPv6 scope collision from WAN", "[fe80::23%wan]:40001", "[fe80::1%wan]:9080", lan, mac, true, false},
	} {
		must(plane.publishAPIObservation())
		source, destination := netip.MustParseAddrPort(test.source), netip.MustParseAddrPort(test.destination)
		observe(source, destination, test.ingress, test.hardware, test.lanHook)
		got, err := plane.resolveAPIClient(source, destination)
		t.Logf("%s: MAC = %v, error = %v", test.name, got, err)
		if (err == nil) != test.want || test.want && got != mac {
			t.Errorf("%s: want accepted = %v", test.name, test.want)
		}
		checkKeylessAdmin(source, destination, test.want)
	}
	source, destination := netip.MustParseAddrPort("192.0.2.23:40001"), netip.MustParseAddrPort("192.0.2.1:9080")
	{ // A tuple and observed MAC identify the peer despite another link's IP.
		must(plane.publishAPIObservation())
		neighbor(wan, "192.0.2.23", other)
		observe(source, destination, lan, mac, true)
		if _, err := plane.resolveAPIClient(source, destination); err != nil {
			t.Errorf("unrelated neighbor on another interface blocked LAN peer: %v", err)
		}
		must(netlink.NeighDel(&netlink.Neigh{LinkIndex: wan.Attrs().Index, IP: net.ParseIP("192.0.2.23")}))
	}
	{ // A current matching packet replaces historical, mismatching evidence.
		must(plane.publishAPIObservation())
		observe(source, destination, lan, other, true)
		if _, err := plane.resolveAPIClient(source, destination); err == nil {
			t.Error("accepted a packet whose MAC differs from the current neighbor")
		}
		observe(source, destination, lan, mac, true)
		if _, err := plane.resolveAPIClient(source, destination); err != nil {
			t.Errorf("historical MAC blocked a current matching observation: %v", err)
		}
	}
	{ // Expired observations cannot authorize a subsequent request.
		must(plane.publishAPIObservation())
		observe(source, destination, lan, mac, true)
		key := apiClientKey(source, destination)
		var client bpfApiClient
		must(plane.core.bpf.ApiClientMap.Lookup(&key, &client))
		client.ObservedAt -= uint64(time.Minute)
		must(plane.core.bpf.ApiClientMap.Update(&key, &client, ebpf.UpdateAny))
		if _, err := plane.resolveAPIClient(source, destination); err == nil {
			t.Fatal("accepted expired LAN evidence")
		}
		checkKeylessAdmin(source, destination, false)
		observe(source, destination, lan, mac, true)
		_, err := plane.resolveAPIClient(source, destination)
		must(err)
		checkKeylessAdmin(source, destination, true)
	}
	{ // Reload retires the previous LAN authorization.
		must(plane.publishAPIObservation())
		observe(source, destination, lan, mac, true)
		must(plane.publishAPIObservation())
		if _, err := plane.resolveAPIClient(source, destination); err == nil {
			t.Fatal("accepted evidence retained across reload")
		}
		checkKeylessAdmin(source, destination, false)
	}
}

func apiIdentityPacket(source, destination netip.AddrPort, mac [6]byte) []byte {
	ipLen, etherType := 40, uint16(unix.ETH_P_IPV6)
	if source.Addr().Is4() {
		ipLen, etherType = 20, unix.ETH_P_IP
	}
	packet := make([]byte, 14+ipLen+20)
	copy(packet[6:12], mac[:])
	binary.BigEndian.PutUint16(packet[12:14], etherType)
	ip := packet[14:]
	if ipLen == 20 {
		ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_TCP
		binary.BigEndian.PutUint16(ip[2:4], 40)
		copy(ip[12:16], source.Addr().AsSlice())
		copy(ip[16:20], destination.Addr().AsSlice())
	} else {
		ip[0], ip[6], ip[7] = 0x60, unix.IPPROTO_TCP, 64
		binary.BigEndian.PutUint16(ip[4:6], 20)
		copy(ip[8:24], source.Addr().AsSlice())
		copy(ip[24:40], destination.Addr().AsSlice())
	}
	tcp := ip[ipLen:]
	binary.NativeEndian.PutUint16(tcp[:2], common.Htons(source.Port()))
	binary.NativeEndian.PutUint16(tcp[2:4], common.Htons(destination.Port()))
	tcp[12], tcp[13] = 5<<4, 0x18 // HTTP data on an established connection.
	return packet
}
