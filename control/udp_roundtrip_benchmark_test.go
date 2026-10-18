// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

// Exercise established userspace ingress through the real reader, task pool,
// endpoint, loopback echo server, reply reader and pooled return socket. Private
// sockmap registration needs BPF privileges; no programs or routes are attached.
// Destination rewriting sends the ingress address to the local echo fixture.
// Initial routing/sniffing and proxy encryption are outside this benchmark.
type udpRoundTripFixture struct {
	clients     []*net.UDPConn
	destination netip.AddrPort
	reply       []byte
}

func newUDPRoundTripFixture(t testing.TB, flows, size int) *udpRoundTripFixture {
	t.Helper()
	sockets, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.SockMap, KeySize: 4, ValueSize: 8, MaxEntries: 2})
	if errors.Is(err, unix.EPERM) {
		t.Skip("BPF privileges required for private ingress sockmap")
	}
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime()
	runtime.shared["listen_socket_map"] = sockets
	t.Cleanup(func() { _ = runtime.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	tasks := newUdpTaskPool(udpPacketWork.execute)
	plane := &ControlPlane{ctx: ctx, udpEndpoints: runtime.udpEndpoints, udpTaskPool: tasks}
	runtime.current = plane
	// Leave the incomplete fixture plane out of runtime.planes; it owns no BPF
	// generation or lifecycle workers and is cleaned up explicitly below.
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(false)
	tcp, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	lc.Control = func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1) })
		return errors.Join(err, optionErr)
	}
	packets, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ingress := packets.(*net.UDPConn)
	t.Cleanup(func() { _ = ingress.Close() })
	destination := ingress.LocalAddr().(*net.UDPAddr).AddrPort()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buffer := make([]byte, udpReceiveBufferSize)
		for {
			n, source, err := echo.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			if _, err := echo.WriteToUDPAddrPort(buffer[:n], source); err != nil {
				return
			}
		}
	}()
	replies := NewAnyfromPool()
	replies.pool[destination] = &Anyfrom{conn: ingress, idleTTL: time.Hour}
	registry := newDomainRegistry(16, time.Hour, func(netip.Addr, []uint32, []uint32) error { return nil }, func(netip.Addr) error { return nil })
	registry.Upsert("bench.test.", destination.Addr(), testBitmap(0), 3600, time.Now())
	fixture := &udpRoundTripFixture{destination: destination, reply: make([]byte, size+1)}
	var readers sync.WaitGroup
	for range flows {
		client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		fixture.clients = append(fixture.clients, client)
		source := client.LocalAddr().(*net.UDPAddr).AddrPort()
		upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		conn := &destinationPacketConn{PacketConn: upstream, original: destination, target: echo.LocalAddr().(*net.UDPAddr).AddrPort()}
		endpoint := &UdpEndpoint{conn: conn, firstDst: destination, domain: "bench.test.", activity: registry.activity,
			NatTimeout: time.Hour, lease: netproxy.NewLease(netproxy.NewResourceRef()),
			traffic: stats.DefaultStore.OpenDeviceConnection(stats.Path{Outbound: "benchmark", Dialer: "loopback"}, false, [6]byte{}),
			handler: func(data []byte, from netip.AddrPort) error {
				if from != destination {
					return fmt.Errorf("unexpected reply source %s", from)
				}
				socket, _, err := replies.GetOrCreate(from, time.Hour)
				if err != nil {
					return err
				}
				_, err = socket.WriteToUDPAddrPortWithDeadline(data, source, time.Now().Add(time.Second))
				return err
			},
		}
		runtime.udpEndpoints.add(source, endpoint)
		readers.Go(func() { _ = endpoint.run(runtime.udpEndpoints, source, destination, conn, nil) })
	}
	ready, served := make(chan bool, 1), make(chan error, 1)
	go func() { served <- runtime.Serve(ready, &Listener{tcpListener: tcp, packetConn: ingress}) }()
	if !<-ready {
		t.Fatal(<-served)
	}
	t.Cleanup(func() {
		cancel()
		_ = runtime.Close()
		tasks.close()
		readers.Wait()
		_ = echo.Close()
		<-echoDone
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	return fixture
}

func (f *udpRoundTripFixture) exchange(payload []byte) error {
	for _, client := range f.clients {
		if _, err := client.WriteToUDPAddrPort(payload, f.destination); err != nil {
			return err
		}
	}
	for _, client := range f.clients {
		// Bound packet loss/failures without changing the production write deadline.
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		n, from, err := client.ReadFromUDPAddrPort(f.reply)
		if err != nil {
			return err
		}
		if from != f.destination || !bytes.Equal(f.reply[:n], payload) {
			return fmt.Errorf("wrong UDP reply from %s (%d bytes)", from, n)
		}
	}
	return nil
}

func TestUDPRoundTripIngressFixture(t *testing.T) {
	fixture := newUDPRoundTripFixture(t, 4, 1200)
	for _, size := range []int{1, 64, 1200} {
		if err := fixture.exchange(bytes.Repeat([]byte{byte(size)}, size)); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkUDPRoundTrip(b *testing.B) {
	for _, flows := range []int{1, 32} {
		for _, size := range []int{64, 1200} {
			b.Run(fmt.Sprintf("flows=%d/bytes=%d", flows, size), func(b *testing.B) {
				fixture := newUDPRoundTripFixture(b, flows, size)
				payload := make([]byte, size)
				if err := fixture.exchange(payload); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(size * flows * 2))
				for b.Loop() {
					if err := fixture.exchange(payload); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(flows*b.N)/b.Elapsed().Seconds(), "roundtrips/s")
			})
		}
	}
}
