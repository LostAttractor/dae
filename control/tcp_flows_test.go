// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func newTestTCPFlows(t *testing.T) *tcpFlows {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	maps := make(map[string]*ebpf.Map)
	for _, name := range []string{"tcp_flow_map", "routing_tuples_map"} {
		mapSpec := spec.Maps[name].Copy()
		mapSpec.Pinning = ebpf.PinNone
		m, err := ebpf.NewMap(mapSpec)
		if errors.Is(err, unix.EPERM) {
			t.Skip("creating a BPF map requires privileges")
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		maps[name] = m
	}
	return &tcpFlows{flows: maps["tcp_flow_map"], handoffs: maps["routing_tuples_map"], grace: 20 * time.Millisecond}
}

// A relayed flow keeps its state through the grace period after its last
// accepted connection finishes, and loses it afterwards unless the tuple has
// been reused meanwhile.
func TestTCPFlowStateEndsAfterRelay(t *testing.T) {
	f := newTestTCPFlows(t)
	key := tuplesKey(netip.MustParseAddrPort("192.168.1.2:40000"), netip.MustParseAddrPort("203.0.113.1:443"), unix.IPPROTO_TCP)
	exists := func() bool {
		t.Helper()
		var flow bpfTcpFlowState
		err := f.flows.Lookup(&key, &flow)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
		return err == nil
	}
	save := func() {
		t.Helper()
		if err := f.flows.Update(&key, bpfTcpFlowState{Owner: 1}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	// Leave time for a deletion that must not happen.
	settle := func() { time.Sleep(5 * f.grace) }
	deleted := func() bool {
		t.Helper()
		for range 100 {
			if !exists() {
				return true
			}
			time.Sleep(f.grace)
		}
		return false
	}

	save()
	f.accept(key)
	f.release(key)
	if !exists() {
		t.Fatal("state deleted before the grace period")
	}
	if !deleted() {
		t.Fatal("state survived its finished relay")
	}

	// The tuple is accepted again before the grace period ends.
	save()
	f.accept(key)
	f.release(key)
	f.accept(key)
	settle()
	if !exists() {
		t.Fatal("finished connection deleted the state of its successor")
	}
	// An older connection of the tuple finishing late changes nothing either.
	f.accept(key)
	f.release(key)
	settle()
	if !exists() {
		t.Fatal("state deleted while a connection of the tuple is live")
	}
	f.release(key)
	if !deleted() {
		t.Fatal("state survived the last connection of the tuple")
	}

	// The kernel forwards a new connection of the tuple itself.
	save()
	f.accept(key)
	f.release(key)
	if err := f.flows.Update(&key, bpfTcpFlowState{Mark: 37}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	settle()
	if !exists() {
		t.Fatal("finished relay deleted the state of a kernel-forwarded connection")
	}

	// A new SYN of the tuple awaits its accept.
	save()
	f.accept(key)
	f.release(key)
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	if err := f.handoffs.Update(&key, bpfRoutingHandoff{Expires: uint32(now.Sec) + 30}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	settle()
	if !exists() {
		t.Fatal("finished connection deleted the state of a pending setup")
	}

	// Shutdown leaves pending states for a restarted dae.
	if err := f.handoffs.Delete(&key); err != nil {
		t.Fatal(err)
	}
	f.accept(key)
	f.release(key)
	f.close()
	settle()
	if !exists() {
		t.Fatal("shutdown deleted a pending state")
	}
	f.accept(key)
	f.release(key)
}
