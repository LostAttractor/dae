// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/network"
	"github.com/vishvananda/netlink"
)

func TestLANListenerRejectsEnslavedLink(t *testing.T) {
	listener := &interfaceListener{address: new(net.TCPAddr)}
	for _, link := range []netlink.Link{
		&netlink.Vlan{Name: "lan", MasterIndex: 2},
		&netlink.Veth{Name: "bond-port", MasterIndex: 3},
	} {
		socket, err := listener.listen(link)
		if socket != nil {
			socket.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "cannot bind enslaved interface "+link.Attrs().Name) {
			t.Fatalf("enslaved interface was not rejected before listening: %v", err)
		}
	}
}

func TestLANListenerBridgePortPreparationKeepsOldListener(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network namespace and NET_ADMIN")
	}
	bridge := &netlink.Bridge{Name: "api-test-br"}
	if err := netlink.LinkAdd(bridge); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(bridge)
	port := &netlink.Dummy{Name: "api-test-port"}
	if err := netlink.LinkAdd(port); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(port)
	if err := netlink.LinkSetMaster(port, bridge); err != nil {
		t.Fatal(err)
	}
	manager, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server, err := ListenInterfaces(":0", []string{"lo"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listener := server.interfaces
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	listener.mu.Lock()
	original := listener.sockets[loopback.Index]
	listener.mu.Unlock()
	if _, _, err := PrepareInterfaces(server, ":0", []string{"lo", port.Name}, manager); err == nil || !strings.Contains(err.Error(), "enslaved") {
		t.Fatalf("bridge port preparation succeeded: %v", err)
	}
	listener.mu.Lock()
	retained := listener.sockets[loopback.Index] == original && listener.pending == nil
	listener.mu.Unlock()
	if !retained {
		t.Fatal("failed bridge preparation replaced the active listener")
	}
	if err := netlink.LinkSetNoMaster(port); err != nil {
		t.Fatal(err)
	}
	_, update, err := PrepareInterfaces(server, ":0", []string{"lo", port.Name}, manager)
	if err != nil {
		t.Fatal(err)
	}
	update.Commit()
	waitServing := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			listener.mu.Lock()
			socket := listener.sockets[port.Index]
			serving := socket != nil && socket.serving
			listener.mu.Unlock()
			if serving == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("listening on bridge port = %t, want %t", serving, want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitServing(true)
	if err := netlink.LinkSetMaster(port, bridge); err != nil {
		t.Fatal(err)
	}
	waitServing(false)
	if err := netlink.LinkSetNoMaster(port); err != nil {
		t.Fatal(err)
	}
	waitServing(true)
}
