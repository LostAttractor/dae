// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"net"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestEntryMultipathMemoryOutlivesRuntimesUntilRelearn(t *testing.T) {
	var listen net.ListenConfig
	listen.SetMultipathTCP(false)
	listener, err := listen.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan string, 4)
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn.RemoteAddr().String()
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		for range accepted {
		}
	})
	global := &config.Global{Mptcp: true}
	option := dialer.NewGlobalOption(global)
	spec := &PathSpec{IPVersion: 4}
	resources := new(Resources)
	pool := &resources.Paths
	// dial reports the protocol of the dialed socket and the connections the
	// TCP-only listener accepted for it: a probe falls back and is kept.
	dial := func(base netproxy.Dialer) (protocol, connections int) {
		t.Helper()
		conn, err := base.DialContext(t.Context(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		raw, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.Control(func(fd uintptr) {
			protocol, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
		})
		for connections = 1; ; connections++ {
			addr, ok := <-accepted
			if !ok {
				t.Fatal("listener stopped accepting")
			}
			if addr == conn.LocalAddr().String() {
				return protocol, connections
			}
		}
	}
	expect := func(base netproxy.Dialer, protocol, connections int, why string) {
		t.Helper()
		if got, made := dial(base); got != protocol || made != connections {
			t.Fatalf("%s: protocol %d after %d connections, want %d after %d", why, got, made, protocol, connections)
		}
	}
	entry := func(pool *PathPool) netproxy.Dialer {
		t.Helper()
		base, err := spec.entryDialer(option, pool)
		if err != nil {
			t.Fatal(err)
		}
		return base
	}
	// Node validation has no pool and keeps MPTCP for every dial.
	unpooled := entry(nil)
	if got, _ := dial(unpooled); got != 262 {
		t.Skipf("MPTCP unavailable: protocol %d", got)
	}
	expect(unpooled, 262, 1, "entry dialer without a pool")
	first := entry(pool)
	expect(first, 262, 1, "probe")
	// The TCP-only listener made the probe fall back, also for a woken runtime.
	expect(first, syscall.IPPROTO_TCP, 1, "known fallback")
	expect(entry(pool), syscall.IPPROTO_TCP, 1, "known fallback in a woken runtime")
	// A rebuilt configuration, as for a resource refresh, keeps it.
	set, err := NewDialerSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewGroupCompiler(set, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	NewGroupMaterializer(compiler, resources, global)
	expect(first, syscall.IPPROTO_TCP, 1, "rebuilt configuration")
	pool.Relearn()
	expect(first, 262, 1, "probe after Relearn")
}
