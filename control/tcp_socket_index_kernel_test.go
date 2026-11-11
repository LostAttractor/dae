// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func testTCPSocketIndex(t *testing.T, capacity uint32) *ebpf.Map {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	index := spec.Maps["tcp_proxy_socket_map"]
	if index == nil || index.Type != ebpf.SockHash || index.Pinning != ebpf.PinNone || index.KeySize != 40 || index.ValueSize != 8 {
		t.Fatalf("socket index must hold unpinned socket references: %+v", index)
	}
	index.MaxEntries = capacity
	m, err := ebpf.NewMap(index)
	if errors.Is(err, unix.EPERM) {
		t.Skip("BPF privileges required")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestTCPSocketIndexLifecycle(t *testing.T) {
	m := testTCPSocketIndex(t, 1)
	accepted, client := relayTestTCPPair(t)
	key := tuplesKey(client.LocalAddr().(*net.TCPAddr).AddrPort(), accepted.LocalAddr().(*net.TCPAddr).AddrPort(), unix.IPPROTO_TCP)
	if err := registerSocket(m, key, accepted); err != nil {
		t.Fatal(err)
	}
	var original uint64
	if err := m.Lookup(key, &original); err != nil || original == 0 {
		t.Fatalf("registered socket cookie: %d, %v", original, err)
	}

	if err := accepted.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := accepted.Read(data[:]); err == nil {
		t.Fatal("indexed socket ignored its read deadline")
	} else if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
		t.Fatalf("indexed read: %v, want timeout", err)
	}
	if err := accepted.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := accepted.Read(data[:]); n != 0 || err != io.EOF {
		t.Fatalf("half-close: %d, %v", n, err)
	}
	var cookie uint64
	if err := m.Lookup(key, &cookie); err != nil || cookie != original {
		t.Fatalf("half-close removed the socket: %d, %v", cookie, err)
	}
	if _, err := accepted.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, data[:]); err != nil || data[0] != 'x' {
		t.Fatalf("half-closed response: %q, %v", data, err)
	}

	replacement, _ := relayTestTCPPair(t)
	other := key
	other.Sport ^= 1
	if err := registerSocket(m, other, replacement); !errors.Is(err, unix.E2BIG) {
		t.Fatalf("full index: %v, want E2BIG", err)
	}
	if err := registerSocket(m, key, replacement); err != nil {
		t.Fatal(err)
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(key, &cookie); err != nil || cookie == original {
		t.Fatalf("closing old socket removed its replacement: %d, %v", cookie, err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(key, &cookie); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("close retained a socket reference: %v", err)
	}
}
