// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func TestHostIdentityPrecedesBusinessMaps(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires root in an isolated network, mount, PID and cgroup environment")
	}
	runtime := NewRuntime()
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	})
	resources, err := runtime.PrepareUserspace(t.Context(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if resources.Interfaces == nil || resources.Outbounds != &runtime.outboundResources || runtime.socketIdentity == nil || len(runtime.shared) != 0 || runtime.nextGeneration != 0 || !runtime.kernelOwned {
		t.Fatal("host preparation loaded business state or omitted userspace resources")
	}
	if len(runtime.kernelLinks.pidLinks) != len(socketIdentityAttachTypes) {
		t.Fatal("outbound sockets would open before all identity hooks")
	}
	entries, err := os.ReadDir(kernelPinPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "links" && entry.Name() != "socket_owner_map" {
			t.Fatalf("host preparation published business pin %q", entry.Name())
		}
	}
	ownerMap := runtime.socketIdentity.SocketOwner
	info, err := ownerMap.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	kernelPID, err := KernelProcessID()
	if err != nil {
		t.Fatal(err)
	}
	checkOwner := func(m *ebpf.Map) {
		t.Helper()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var owner bpfPidPname
		var lookupErr error
		if err := raw.Control(func(fd uintptr) { lookupErr = m.Lookup(uint32(fd), &owner) }); err != nil {
			t.Fatal(err)
		}
		if lookupErr != nil || owner.Pid != kernelPID {
			t.Fatalf("socket owner=%+v, want kernel PID %d: %v", owner, kernelPID, lookupErr)
		}
	}
	checkOwner(ownerMap)
	preparation, err := PrepareControlPlane(t.Context(), runtime, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer preparation.Close()
	info, err = preparation.bpf.SocketOwnerMap.Info()
	if err != nil {
		t.Fatal(err)
	}
	businessID, _ := info.ID()
	if businessID != id || runtime.socketIdentity != nil || preparation.bpf.DomainRoutingMap == nil {
		t.Fatal("business installation replaced early socket identity or retained temporary descriptors")
	}
	checkOwner(preparation.bpf.SocketOwnerMap)
}
