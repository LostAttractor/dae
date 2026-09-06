package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/settings"
	"golang.org/x/sys/unix"
)

// Exercise the same map publication as production; only the kernel programs
// are unnecessary for the Go transaction and relay tests.
func newTestDeviceRoutes(t *testing.T) *deviceRoutes {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	outer, err := ebpf.NewMap(spec.Maps["device_routes_map"])
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating a BPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outer.Close() })
	inner, err := ebpf.NewMap(spec.Maps["unused_device_routes"])
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	if err := outer.Update(uint32(0), inner, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	return &deviceRoutes{outer: outer}
}

func TestClientMembershipConnectionPolicy(t *testing.T) {
	for _, closeOld := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "close"}[closeOld], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			store, err := settings.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			c := newAPITestPlane(t, store)
			c.closeOnRouteChange, c.deviceRoutes = closeOld, newTestDeviceRoutes(t)
			mac, _ := testClientMAC(netip.AddrPort{}, netip.AddrPort{})
			result := &bpfRoutingResult{Mac: mac}
			old, err := c.deviceRoutes.acquire(result)
			if err != nil {
				t.Fatal(err)
			}
			other, err := c.deviceRoutes.acquire(&bpfRoutingResult{Mac: [6]byte{2, 0, 0, 0, 0, 11}})
			if err != nil {
				t.Fatal(err)
			}
			request := func(method string) {
				t.Helper()
				w := apiTestRequest(c.apiHandler(testClientMAC), method, "/api/device/sets/gaming", "", "")
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
			}
			request("DELETE") // absent membership: no close
			if old.AbortCause() != nil {
				t.Fatal("no-op leave closed connections")
			}
			request("PUT")
			if (old.AbortCause() != nil) != closeOld {
				t.Fatalf("old device: %v", old.AbortCause())
			}
			if closeOld {
				if _, err := c.deviceRoutes.acquire(result); !errors.Is(err, errRouteChanged) {
					t.Fatalf("stale setup accepted: %v", err)
				}
				result.RouteEpoch++
			}
			current, err := c.deviceRoutes.acquire(result)
			if err != nil {
				t.Fatal(err)
			}
			request("PUT") // no-op join
			if current.AbortCause() != nil {
				t.Fatal("no-op join closed connections")
			}
			// File edits follow the same policy and ignore unreferenced sets.
			if err := os.WriteFile(path, []byte(`{"selectors":{},"mitm":{},"clients":{"gaming":["02:00:00:00:00:0a"],"unused":["02:00:00:00:00:0a"]}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := c.ReloadRuntimeSettings(); err != nil {
				t.Fatal(err)
			}
			if current.AbortCause() != nil {
				t.Fatal("unreferenced membership closed connections")
			}
			if err := os.WriteFile(path, []byte(`{"selectors":{},"mitm":{},"clients":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := c.ReloadRuntimeSettings(); err != nil {
				t.Fatal(err)
			}
			if (current.AbortCause() != nil) != closeOld {
				t.Fatal("file reload lost close policy")
			}
			if other.AbortCause() != nil {
				t.Fatal("membership change closed another device")
			}
		})
	}
}

func TestDeviceRouteCommitAndRollback(t *testing.T) {
	d := newTestDeviceRoutes(t)
	outer := d.outer
	a, b := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
	lease, err := d.acquire(&bpfRoutingResult{Mac: a})
	if err != nil {
		t.Fatal(err)
	}
	changed := map[[6]byte]bool{a: true, b: true}
	check := func(gated bool, epoch uint64) {
		t.Helper()
		var table *ebpf.Map
		if err := outer.Lookup(uint32(0), &table); err != nil {
			t.Fatal(err)
		}
		defer table.Close()
		for mac := range changed {
			var state bpfDeviceRouteState
			err := table.Lookup(mac, &state)
			if !gated && epoch == 0 && errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			if err != nil || state.Epoch != epoch || (state.Updating != 0) != gated {
				t.Fatalf("device state %+v: %v", state, err)
			}
		}
	}
	failed := errors.New("settings rejected")
	if err := d.change(changed, func(commit func() error) error { check(true, 0); return failed }); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	check(false, 0)
	if lease.AbortCause() != nil {
		t.Fatal("failed transaction aborted old flows")
	}
	if err := d.change(changed, func(commit func() error) error { check(true, 0); return commit() }); err != nil {
		t.Fatal(err)
	}
	check(false, 1)
	if lease.AbortCause() == nil {
		t.Fatal("committed change did not abort old flows")
	}
	if _, err := d.acquire(&bpfRoutingResult{Mac: b, RouteEpoch: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceRouteChangeInterruptsTCPSniffing(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: uint32(unsafe.Sizeof(bpfTuplesKey{})), ValueSize: uint32(unsafe.Sizeof(bpfRoutingResult{})), MaxEntries: 8})
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating a BPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	left, client := relayTestTCPPair(t)
	src, dst := left.RemoteAddr().(*net.TCPAddr).AddrPort(), left.LocalAddr().(*net.TCPAddr).AddrPort()
	key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: unix.IPPROTO_TCP}
	key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	if err := m.Update(key, bpfRoutingResult{Mac: mac}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	c := &ControlPlane{deviceRoutes: newTestDeviceRoutes(t), sniffingTimeout: time.Minute, core: &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{RoutingTuplesMap: m}}}}}
	finished := make(chan *tcpRelay, 1)
	go func() { relay, _ := c.prepareTCPRelay(context.Background(), left); finished <- relay }()
	deadline := time.Now().Add(time.Second)
	for {
		c.deviceRoutes.mu.Lock()
		registered := c.deviceRoutes.devices[mac] != nil
		c.deviceRoutes.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sniffing did not register device ownership")
		}
		time.Sleep(time.Millisecond)
	}
	if err := c.deviceRoutes.change(map[[6]byte]bool{mac: true}, func(commit func() error) error { return commit() }); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, unix.ECONNRESET) {
		t.Fatalf("sniffing client was not reset: %v", err)
	}
	select {
	case relay := <-finished:
		if relay != nil {
			t.Fatal("aborted sniffing created a relay")
		}
	case <-time.After(time.Second):
		t.Fatal("route change waited for sniffing timeout")
	}
}
