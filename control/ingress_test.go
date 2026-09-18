package control

import (
	"errors"
	"net"
	"strings"
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
			// Only publication and descriptor ownership matter here; no BPF
			// program uses the descriptors in this serving-loop test.
			m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 2})
			if errors.Is(err, unix.EPERM) {
				t.Skip("creating a BPF map requires privileges")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			c := newLifecycleTestControlPlane(new(UdpEndpointPool))
			c.core = &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{ListenSocketMap: m}}}}
			defer c.retireTraffic()
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
				sockets := &c.ingress.tcp
				if test.name == "UDP" {
					sockets = &c.ingress.udp
				}
				if err := sockets.closeFuncs[1](); err != nil {
					t.Fatal(err)
				}
			} else if err := c.retireTraffic(); err != nil {
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
				if c.ctx.Err() == nil {
					t.Fatal("failed serving plane retained an active context")
				}
			case <-time.After(time.Second):
				t.Fatal("Serve did not return after ingress stopped")
			}
		})
	}
}
