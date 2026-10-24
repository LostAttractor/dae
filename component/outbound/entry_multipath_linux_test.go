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
	address := net.JoinHostPort("127.0.0.1", entryAddressListener(t))
	global := &config.Global{Mptcp: true}
	option := dialer.NewGlobalOption(global)
	spec := &PathSpec{IPVersion: 4}
	resources := new(Resources)
	pool := &resources.Paths
	protocol := func(base netproxy.Dialer) int {
		t.Helper()
		conn, err := base.DialContext(t.Context(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		raw, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		protocol := -1
		_ = raw.Control(func(fd uintptr) {
			protocol, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
		})
		return protocol
	}
	entry := func(pool *PathPool) netproxy.Dialer {
		t.Helper()
		base, err := spec.entryDialer(option, pool)
		if err != nil {
			t.Fatal(err)
		}
		return base
	}
	first := entry(pool)
	if got := protocol(first); got != 262 {
		t.Skipf("MPTCP unavailable: protocol %d", got)
	}
	// The TCP-only listener made the probe fall back, also for a woken runtime.
	for _, base := range []netproxy.Dialer{first, entry(pool)} {
		if got := protocol(base); got != syscall.IPPROTO_TCP {
			t.Fatalf("known fallback dialed with protocol %d", got)
		}
	}
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
	if got := protocol(first); got != syscall.IPPROTO_TCP {
		t.Fatalf("rebuilt configuration forgot the fallback; protocol %d", got)
	}
	pool.Relearn()
	if got := protocol(first); got != 262 {
		t.Fatalf("Relearn kept the fallback; protocol %d", got)
	}
	// Node validation has no pool and keeps MPTCP for every dial.
	unpooled := entry(nil)
	for range 2 {
		if got := protocol(unpooled); got != 262 {
			t.Fatalf("entry dialer without a pool used protocol %d", got)
		}
	}
}
