package control

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestServeReportsIngressFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure string
	}{
		{name: "TCP", failure: "accept TCP connection"},
		{name: "UDP", failure: "read UDP datagram"},
		{name: "retirement"},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.SockMap, KeySize: 4, ValueSize: 8, MaxEntries: 2})
			if errors.Is(err, unix.EPERM) {
				t.Skip("creating a BPF map requires privileges")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			lc := net.ListenConfig{}
			lc.SetMultipathTCP(false)
			tcp, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			c := NewRuntime()
			c.shared["listen_socket_map"], err = m.Clone()
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ready, done := make(chan bool, 1), make(chan error, 1)
			go func() { done <- c.Serve(ready, &Listener{tcpListener: tcp, packetConn: udp}) }()
			select {
			case started := <-ready:
				if !started {
					t.Fatal(<-done)
				}
			case <-time.After(time.Second):
				t.Fatal("ingress did not start")
			}
			if test.failure != "" {
				// Simulate a failed serving descriptor while the plane is active.
				closeSocket := tcp.Close
				if test.name == "UDP" {
					closeSocket = udp.Close
				}
				if err := closeSocket(); err != nil {
					t.Fatal(err)
				}
			} else if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if test.failure == "" {
					if err != nil {
						t.Fatalf("normal retirement reported failure: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), test.failure) {
					t.Fatalf("ingress failure = %v, want %q", err, test.failure)
				}
			case <-time.After(time.Second):
				t.Fatal("Serve did not return after ingress stopped")
			}
		})
	}
}

func TestRuntimeListenerUsesSockmapCompatibleTCP(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=1")
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.SockMap, KeySize: 4, ValueSize: 8, MaxEntries: 2})
	if errors.Is(err, unix.EPERM) {
		t.Skip("BPF privileges required")
	}
	if err != nil {
		t.Fatal(err)
	}
	r := NewRuntime()
	r.shared["listen_socket_map"] = m
	t.Cleanup(func() { _ = r.Close() })
	ready, done := make(chan bool, 1), make(chan error, 1)
	go func() { _, err := r.ListenAndServe(ready, 0); done <- err }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal(<-done)
		}
	case err := <-done:
		t.Fatalf("listen failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("listener did not start")
	}
	raw, err := r.listener.tcpListener.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		protocol, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
		if err != nil || protocol != unix.IPPROTO_TCP {
			t.Errorf("transparent listener protocol=%d, %v", protocol, err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
