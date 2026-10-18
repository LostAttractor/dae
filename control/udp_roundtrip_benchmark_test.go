// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
	clients      []*net.UDPConn
	destination  netip.AddrPort
	reply        []byte
	replySources []netip.AddrPort
	clock        time.Time
	sequence     uint64
	latencies    []time.Duration
	sampleIndex  int
}

func newUDPRoundTripFixture(t testing.TB, flows, size int) *udpRoundTripFixture {
	return newUDPRoundTripTargets(t, flows, size, 1)
}

func newUDPRoundTripTargets(t testing.TB, flows, size, targets int) *udpRoundTripFixture {
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
	if err := ingress.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ingress.Close() })
	destination := ingress.LocalAddr().(*net.UDPAddr).AddrPort()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	if err := echo.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
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
	// Separate reply sockets model original destinations after transparent
	// ingress. This keeps the same single ingress reader across target counts.
	replySources := make([]netip.AddrPort, targets)
	for i := range replySources {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		replySources[i] = socket.LocalAddr().(*net.UDPAddr).AddrPort()
		replies.pool[replySources[i]] = &Anyfrom{conn: socket, idleTTL: time.Hour}
	}
	registry := newDomainRegistry(16, time.Hour, func(netip.Addr, []uint32, []uint32) error { return nil }, func(netip.Addr) error { return nil })
	registry.Upsert("bench.test.", destination.Addr(), testBitmap(0), 3600, time.Now())
	fixture := &udpRoundTripFixture{destination: destination, reply: make([]byte, size+1), clock: time.Now(), latencies: make([]time.Duration, 0, 32768)}
	var readers sync.WaitGroup
	for i := range flows {
		replySource := replySources[i%targets]
		fixture.replySources = append(fixture.replySources, replySource)
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
				socket, _, err := replies.GetOrCreate(replySource, time.Hour)
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
	for i, client := range f.clients {
		// Bound packet loss/failures without changing the production write deadline.
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		n, from, err := client.ReadFromUDPAddrPort(f.reply)
		if err != nil {
			return err
		}
		if from != f.replySources[i] || !bytes.Equal(f.reply[:n], payload) {
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

// Each operation exchanges window packets per flow. The payload carries a
// sequence and source ID; timeout, duplicates and cross-flow replies fail the
// benchmark instead of inflating throughput. Samples bound histogram memory.
func (f *udpRoundTripFixture) exchangeWindow(payload []byte, window int) error {
	base := f.sequence
	f.sequence += uint64(window)
	for packet := range window {
		for i, client := range f.clients {
			binary.LittleEndian.PutUint64(payload, uint64(time.Since(f.clock)))
			binary.LittleEndian.PutUint64(payload[8:], base+uint64(packet))
			binary.LittleEndian.PutUint64(payload[16:], uint64(i))
			if _, err := client.WriteToUDPAddrPort(payload, f.destination); err != nil {
				return err
			}
		}
	}
	for i, client := range f.clients {
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		var seen uint64
		for range window {
			n, from, err := client.ReadFromUDPAddrPort(f.reply)
			if err != nil {
				return err
			}
			if n != len(payload) || from != f.replySources[i] || binary.LittleEndian.Uint64(f.reply[16:]) != uint64(i) || !bytes.Equal(f.reply[24:n], payload[24:]) {
				return fmt.Errorf("wrong UDP reply from %s (%d bytes)", from, n)
			}
			sequence := binary.LittleEndian.Uint64(f.reply[8:])
			if sequence < base || sequence >= base+uint64(window) || seen&(1<<(sequence-base)) != 0 {
				return fmt.Errorf("duplicate or unexpected UDP sequence %d", sequence)
			}
			seen |= 1 << (sequence - base)
			latency := time.Since(f.clock) - time.Duration(binary.LittleEndian.Uint64(f.reply))
			if len(f.latencies) < cap(f.latencies) {
				f.latencies = append(f.latencies, latency)
			} else {
				f.latencies[f.sampleIndex%len(f.latencies)] = latency
			}
			f.sampleIndex++
		}
	}
	return nil
}

func TestUDPRoundTripMultipleTargets(t *testing.T) {
	fixture := newUDPRoundTripTargets(t, 8, 1200, 4)
	for range 4 {
		if err := fixture.exchangeWindow(make([]byte, 1200), 8); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkUDPRoundTrip(b *testing.B) {
	for _, scenario := range []struct{ flows, targets, window int }{{1, 1, 1}, {32, 1, 1}, {32, 32, 1}, {32, 1, 8}, {32, 32, 8}} {
		for _, size := range []int{64, 1200} {
			b.Run(fmt.Sprintf("flows=%d/targets=%d/window=%d/bytes=%d", scenario.flows, scenario.targets, scenario.window, size), func(b *testing.B) {
				fixture := newUDPRoundTripTargets(b, scenario.flows, size, scenario.targets)
				payload := make([]byte, size)
				if err := fixture.exchangeWindow(payload, scenario.window); err != nil {
					b.Fatal(err)
				}
				fixture.latencies = fixture.latencies[:0]
				fixture.sampleIndex = 0
				packets := scenario.flows * scenario.window
				b.ReportAllocs()
				b.SetBytes(int64(size * packets * 2))
				for b.Loop() {
					if err := fixture.exchangeWindow(payload, scenario.window); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(packets*b.N)/b.Elapsed().Seconds(), "roundtrips/s")
				slices.Sort(fixture.latencies)
				b.ReportMetric(float64(fixture.latencies[(len(fixture.latencies)-1)*95/100])/float64(time.Microsecond), "p95-us")
			})
		}
	}
}
