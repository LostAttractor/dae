// SPDX-License-Identifier: AGPL-3.0-only

package control

// The queueing experiment drives the real UDP task pool, packet writes and
// outbound chain (direct TCP, Shadowsocks 2022, sing-mux smux) between two
// network namespaces that scripts/tests/queueing sets up. The client plays
// the LAN and dae; the server relays with in-tree fixtures and reflects
// probes. Both run only with DAE_QUEUE_EXP=1; see the script for variables.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022/ss2022test"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
	quic "github.com/daeuniverse/quic-go"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	qexpProxyPort       = 8388
	qexpGamePort        = 27015 // UDP probes, reflected
	qexpFloodPort       = 27016 // UDP flood, counted
	qexpQUICPort        = 443
	qexpBulkPort        = 5201 // TCP upload sink
	qexpDownloadPort    = 5202 // TCP download source
	qexpTTFBPort        = 5203 // TCP first-byte responder
	qexpInteractivePort = 5204 // TCP probes, reflected
	qexpProbeSize       = 100
	qexpProbeInterval   = 16 * time.Millisecond
	qexpReportInterval  = 100 * time.Millisecond
	qexpChunk           = 32 << 10 // as the relay's copy buffer
)

var qexpPSK = bytes.Repeat([]byte{0x51}, ss2022test.KeySize)

func qexpEnv(t *testing.T, name, fallback string) string {
	if os.Getenv("DAE_QUEUE_EXP") != "1" {
		t.Skip("queueing experiment: set DAE_QUEUE_EXP=1 and run scripts/tests/queueing")
	}
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func qexpDuration(t *testing.T, name, fallback string) time.Duration {
	d, err := time.ParseDuration(qexpEnv(t, name, fallback))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func qexpAddr(host string, port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

func qexpNow() int64 { return time.Now().UnixNano() }

func qexpTLS(t *testing.T) *tls.Config {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, NextProtos: []string{"qexp"}}
}

// TestQueueingExperimentCake installs cake on QEXP_CAKE_DEV at QEXP_CAKE_RATE
// (tc units: kbit, mbit, gbit) as the router's cu has it. tc's rtt keyword
// also sets the target to rtt/20; the router sets only the RTT and keeps the
// 5 ms default target, so both are sent here.
func TestQueueingExperimentCake(t *testing.T) {
	link, err := netlink.LinkByName(qexpEnv(t, "QEXP_CAKE_DEV", ""))
	if err != nil {
		t.Fatal(err)
	}
	rate := qexpEnv(t, "QEXP_CAKE_RATE", "")
	var bits uint64
	for unit, scale := range map[string]uint64{"kbit": 1e3, "mbit": 1e6, "gbit": 1e9} {
		if number, ok := strings.CutSuffix(rate, unit); ok {
			if bits, err = strconv.ParseUint(number, 10, 64); err != nil {
				t.Fatal(err)
			}
			bits *= scale
		}
	}
	if bits == 0 {
		t.Fatalf("rate %q", rate)
	}
	// Attribute types and values of linux/pkt_sched.h.
	const (
		baseRate64, diffservMode, flowMode, overhead, rtt, target, nat, raw, wash, splitGSO = 2, 3, 5, 6, 7, 8, 11, 12, 13, 17
		diffserv3, tripleIsolate                                                            = 0, 7
	)
	options := nl.NewRtAttr(nl.TCA_OPTIONS, nil)
	options.AddRtAttr(baseRate64, nl.Uint64Attr(bits/8))
	options.AddRtAttr(diffservMode, nl.Uint32Attr(diffserv3))
	options.AddRtAttr(flowMode, nl.Uint32Attr(tripleIsolate))
	options.AddRtAttr(nat, nl.Uint32Attr(0))
	options.AddRtAttr(wash, nl.Uint32Attr(0))
	options.AddRtAttr(splitGSO, nl.Uint32Attr(1))
	options.AddRtAttr(overhead, nl.Uint32Attr(0))
	options.AddRtAttr(raw, nl.Uint32Attr(0))
	options.AddRtAttr(rtt, nl.Uint32Attr(50000))   // µs
	options.AddRtAttr(target, nl.Uint32Attr(5000)) // µs
	req := nl.NewNetlinkRequest(unix.RTM_NEWQDISC, unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	req.AddData(&nl.TcMsg{Family: unix.AF_UNSPEC, Ifindex: int32(link.Attrs().Index), Parent: netlink.HANDLE_ROOT})
	req.AddData(nl.NewRtAttr(nl.TCA_KIND, nl.ZeroTerminated("cake")))
	req.AddData(options)
	if _, err := req.Execute(unix.NETLINK_ROUTE, 0); err != nil {
		t.Fatal(err)
	}
}

// TestQueueingExperimentServer relays Shadowsocks 2022 and smux to the
// experiment's targets until it is terminated.
func TestQueueingExperimentServer(t *testing.T) {
	host := qexpEnv(t, "QEXP_SERVER", "127.0.0.1")
	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	listen := func(port int) net.Listener {
		config := net.ListenConfig{}
		config.SetMultipathTCP(false) // as the measured proxy servers
		listener, err := config.Listen(ctx, "tcp", qexpAddr(host, port).String())
		if err != nil {
			t.Fatal(err)
		}
		context.AfterFunc(ctx, func() { _ = listener.Close() })
		return listener
	}
	serve := func(port int, handle func(net.Conn)) {
		listener := listen(port)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					handle(conn)
				}()
			}
		}()
	}
	for _, port := range []int{qexpGamePort, qexpFloodPort} {
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(qexpAddr(host, port)))
		if err != nil {
			t.Fatal(err)
		}
		context.AfterFunc(ctx, func() { _ = conn.Close() })
		if err := qexpReceiveBuffer(conn); err != nil {
			t.Fatal(err)
		}
		go qexpReflect(conn)
	}
	serve(qexpBulkPort, qexpSink)
	serve(qexpDownloadPort, func(conn net.Conn) {
		if _, err := conn.Read(make([]byte, 1)); err != nil {
			return
		}
		buf := make([]byte, qexpChunk)
		for {
			if _, err := conn.Write(buf); err != nil {
				return
			}
		}
	})
	serve(qexpTTFBPort, func(conn net.Conn) {
		b := make([]byte, 1)
		if _, err := conn.Read(b); err == nil {
			_, _ = conn.Write(b)
			_, _ = conn.Read(b) // until the client closes
		}
	})
	serve(qexpInteractivePort, func(conn net.Conn) {
		record := make([]byte, qexpProbeSize)
		for {
			if _, err := io.ReadFull(conn, record); err != nil {
				return
			}
			if _, err := conn.Write(binary.BigEndian.AppendUint64(record[:12:12], uint64(qexpNow()))); err != nil {
				return
			}
		}
	})
	quicListener, err := quic.ListenAddr(qexpAddr(host, qexpQUICPort).String(), qexpTLS(t), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { _ = quicListener.Close() })
	go func() {
		for {
			conn, err := quicListener.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				stream, err := conn.AcceptStream(ctx)
				if err == nil {
					qexpSink(&qexpQUICStream{stream, conn})
				}
				_ = conn.CloseWithError(0, "")
			}()
		}
	}()
	serve(qexpProxyPort, func(raw net.Conn) {
		conn, target, err := ss2022test.Accept(raw, qexpPSK)
		if err != nil {
			t.Logf("accept: %v", err)
			return
		}
		if target != "sp.mux.sing-box.arpa:444" {
			qexpRelayTCP(conn, target)
			return
		}
		var header [2]byte // version, protocol
		if _, err := io.ReadFull(conn, header[:]); err != nil || header[1] != byte(singmux.ProtocolSmux) {
			return
		}
		session := smuxtest.Server(conn)
		defer session.Close()
		for {
			stream, err := session.Accept()
			if err != nil {
				return
			}
			go qexpRelayStream(stream)
		}
	})
	<-ctx.Done()
}

type qexpQUICStream struct {
	*quic.Stream
	conn *quic.Conn
}

func (s *qexpQUICStream) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *qexpQUICStream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// qexpSink discards an upload and reports the bytes it received so far.
func qexpSink(conn net.Conn) {
	var received atomic.Uint64
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(qexpReportInterval):
			}
			if _, err := conn.Write(binary.BigEndian.AppendUint64(nil, received.Load())); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		n, err := conn.Read(buf)
		received.Add(uint64(n))
		if err != nil {
			return
		}
	}
}

// qexpReceiveBuffer keeps a server socket from dropping what reached it;
// run.sh rejects a run whose server namespace dropped UDP anyway.
func qexpReceiveBuffer(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 16<<20)
	}); err != nil {
		return err
	}
	return optErr
}

// qexpReflect counts datagrams by source. It reflects a probe with its
// receive time and that count, and answers a report request with the count.
func qexpReflect(conn *net.UDPConn) {
	counts := make(map[netip.AddrPort]uint64)
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		var reply []byte
		switch buf[0] {
		case 'R':
			reply = binary.BigEndian.AppendUint64([]byte{'R'}, counts[from])
		case 'P':
			counts[from]++
			if n >= 13 {
				reply = binary.BigEndian.AppendUint64(buf[:13:13], uint64(qexpNow()))
				reply = binary.BigEndian.AppendUint64(reply, counts[from])
			}
		default:
			counts[from]++
		}
		if reply != nil {
			_, _ = conn.WriteToUDPAddrPort(reply, from)
		}
	}
}

func qexpRelayTCP(conn net.Conn, target string) {
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer upstream.Close()
	go func() {
		_, _ = io.Copy(upstream, conn)
		_ = upstream.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(conn, upstream)
}

// qexpRelayStream serves one sing-mux stream: TCP to its target, or UDP
// datagrams with their addresses through a socket of its own.
func qexpRelayStream(stream *smuxtest.Stream) {
	defer stream.Close()
	var flags uint16
	if err := binary.Read(stream, binary.BigEndian, &flags); err != nil {
		return
	}
	target, err := socks5.ReadAddr(stream)
	if err != nil {
		return
	}
	if _, err := stream.Write([]byte{0}); err != nil {
		return
	}
	if flags&1 == 0 {
		qexpRelayTCP(stream, target.String())
		return
	}
	socket, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}
	defer socket.Close()
	if qexpReceiveBuffer(socket) != nil {
		return
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			frame, _ := socks5.AppendNetAddr(nil, net.UDPAddrFromAddrPort(from))
			frame = binary.BigEndian.AppendUint16(frame, uint16(n))
			if _, err := stream.Write(append(frame, buf[:n]...)); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		addr, err := socks5.ReadAddr(stream)
		if err != nil {
			return
		}
		var length uint16
		if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
			return
		}
		if _, err := io.ReadFull(stream, buf[:length]); err != nil {
			return
		}
		to, err := net.ResolveUDPAddr("udp", addr.String())
		if err == nil {
			_, _ = socket.WriteToUDP(buf[:length], to)
		}
	}
}

// qexpCarriers dials the TCP carriers, keeps their sockets for sampling and
// makes each carrier write spin for writerDelay first, as a busy writer.
type qexpCarriers struct {
	netproxy.Dialer
	writerDelay time.Duration
	mu          sync.Mutex
	sockets     []syscall.RawConn
}

func (d *qexpCarriers) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, addr)
	if err != nil || !strings.HasPrefix(network, "tcp") {
		return conn, err
	}
	if raw, err := conn.(syscall.Conn).SyscallConn(); err == nil {
		d.mu.Lock()
		d.sockets = append(d.sockets, raw)
		d.mu.Unlock()
	}
	if d.writerDelay > 0 {
		return &qexpBusyWriter{conn, d.writerDelay}, nil
	}
	return conn, nil
}

// notsent samples the bytes each carrier holds that it has not sent. On a
// fallen back MPTCP socket SIOCOUTQNSD also counts the subflow's bytes in
// flight, which TCP_INFO (the subflow's) gives.
func (d *qexpCarriers) notsent() (samples []float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, raw := range d.sockets {
		_ = raw.Control(func(fd uintptr) {
			n, err := unix.IoctlGetInt(int(fd), unix.SIOCOUTQNSD)
			if err != nil {
				return
			}
			if proto, _ := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL); proto == unix.IPPROTO_MPTCP {
				info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
				if err != nil {
					return
				}
				n -= int(info.Bytes_sent - info.Bytes_retrans - info.Bytes_acked)
			}
			samples = append(samples, float64(n))
		})
	}
	return samples
}

// qexpBusyWriter must expose its carrier's socket to every lookup the
// carrier path makes, as ReadPassthrough does for reads; otherwise the
// variant would measure a carrier that lost its socket, not a busy writer.
type qexpBusyWriter struct {
	net.Conn
	delay time.Duration
}

func (c *qexpBusyWriter) Write(b []byte) (int, error) {
	for start := time.Now(); time.Since(start) < c.delay; {
	}
	return c.Conn.Write(b)
}

// ReadPassthrough keeps receive tuning: reads are unchanged.
func (c *qexpBusyWriter) ReadPassthrough() net.Conn { return c.Conn }

// qexpFlow is a LAN UDP source: its endpoint's replies arrive on replies.
type qexpFlow struct {
	src, dst netip.AddrPort
	replies  chan []byte
	sent     atomic.Uint64
	echoed   atomic.Uint64 // probes reflected back
	dropped  atomic.Uint64 // replies the LAN reader was too slow for
}

func (f *qexpFlow) trySend(data []byte, _ netip.AddrPort) bool {
	select {
	case f.replies <- bytes.Clone(data):
	default:
		f.dropped.Add(1)
	}
	return true
}

func (f *qexpFlow) send(data []byte, from netip.AddrPort) error {
	f.trySend(data, from)
	return nil
}

// qexpLANConn is a LAN client's UDP socket: writes enter the task pool as
// ingress packets do, reads return the flow's replies.
type qexpLANConn struct {
	plane  *ControlPlane
	flow   *qexpFlow
	closed chan struct{}
	once   sync.Once
}

func (c *qexpLANConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.flow.sent.Add(1)
	c.plane.enqueueUDPPacket(b, c.flow.src, c.flow.dst, nil)
	return len(b), nil
}

func (c *qexpLANConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-c.flow.replies:
		return copy(b, p), net.UDPAddrFromAddrPort(c.flow.dst), nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *qexpLANConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *qexpLANConn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.flow.src) }

// SetReadDeadline in the past unblocks ReadFrom as Close does.
func (c *qexpLANConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() && !t.After(time.Now()) {
		return c.Close()
	}
	return nil
}
func (c *qexpLANConn) SetDeadline(t time.Time) error  { return c.SetReadDeadline(t) }
func (*qexpLANConn) SetWriteDeadline(time.Time) error { return nil }

type qexpStats struct {
	N                  int
	P50, P90, P99, Max float64
}

func qexpSummary(samples []float64) *qexpStats {
	if len(samples) == 0 {
		return nil
	}
	slices.Sort(samples)
	at := func(q float64) float64 { return samples[min(len(samples)-1, int(q*float64(len(samples))))] }
	return &qexpStats{len(samples), at(.5), at(.9), at(.99), samples[len(samples)-1]}
}

// qexpRecorder keeps samples taken inside the measurement window, also by
// the window's first and last quarter (NAME_q1, NAME_q4) to show a trend.
// late counts the samples that arrived after the load stopped: their
// delays were cut short.
type qexpRecorder struct {
	mu      sync.Mutex
	from    int64
	to      int64
	stopped atomic.Int64 // when the load stopped; 0 before
	samples map[string][]float64
	late    map[string]int
}

func (r *qexpRecorder) add(name string, at int64, value float64) {
	if at < r.from || at >= r.to {
		return
	}
	late := 0
	if stopped := r.stopped.Load(); stopped != 0 && qexpNow() >= stopped {
		late = 1
	}
	quarter := (r.to - r.from) / 4
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples[name] = append(r.samples[name], value)
	r.late[name] += late
	switch {
	case at < r.from+quarter:
		r.samples[name+"_q1"] = append(r.samples[name+"_q1"], value)
	case at >= r.to-quarter:
		r.samples[name+"_q4"] = append(r.samples[name+"_q4"], value)
	}
}

// qexpCounter follows a cumulative count the server reports and remembers
// it at the edges of the window.
type qexpCounter struct {
	latest, first, last atomic.Uint64
}

func (c *qexpCounter) follow(r io.Reader) {
	var b [8]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return
		}
		c.latest.Store(binary.BigEndian.Uint64(b[:]))
	}
}

func (c *qexpCounter) mbit(window time.Duration) float64 {
	return float64(c.last.Load()-c.first.Load()) * 8 / window.Seconds() / 1e6
}

// TestQueueingExperimentClient plays the LAN and dae: it runs the workload
// of QEXP_WORKLOAD through the outbound and writes a JSON report to
// QEXP_OUT.
func TestQueueingExperimentClient(t *testing.T) {
	host := qexpEnv(t, "QEXP_SERVER", "127.0.0.1")
	warmup, duration := qexpDuration(t, "QEXP_WARMUP", "3s"), qexpDuration(t, "QEXP_DURATION", "20s")
	returnDelay, writerDelay := qexpDuration(t, "QEXP_RETURN_DELAY", "0s"), qexpDuration(t, "QEXP_WRITER_DELAY", "0s")
	maxConnections, err := strconv.Atoi(qexpEnv(t, "QEXP_MAX_CONNECTIONS", "0"))
	if err != nil {
		t.Fatal(err)
	}
	workload := make(map[string]int)
	for item := range strings.FieldsFuncSeq(qexpEnv(t, "QEXP_WORKLOAD", "game,bulk:4"), func(r rune) bool { return r == ',' }) {
		name, value, _ := strings.Cut(item, ":")
		workload[name] = 1
		if value != "" {
			if workload[name], err = strconv.Atoi(value); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	option := direct.Option{}
	if qexpEnv(t, "QEXP_MPTCP", "0") == "1" {
		// As configured on the router: MPTCP first, remembered per server.
		option.Mptcp, option.Multipath = true, new(direct.MultipathMemory)
	}
	carriers := &qexpCarriers{Dialer: direct.NewDirectDialer(option), writerDelay: writerDelay}
	proxy, err := shadowsocks_2022.NewDialer(carriers, protocol.Header{
		ProxyAddress: qexpAddr(host, qexpProxyPort).String(), Cipher: ss2022test.Method, Password: base64.StdEncoding.EncodeToString(qexpPSK),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := &singmux.Mux{Dialer: proxy, MaxConnections: maxConnections}
	defer mux.Close()
	if err := mux.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	// Stand in for the daemon's connectivity checker, which connects the
	// sessions the pool asks for.
	go func() {
		for event := range mux.WatchState(ctx) {
			if event.Accepting && event.RecoveryRequired && event.RecoveryExecutor != netproxy.RecoveryLibraryManaged {
				_ = mux.Connect(ctx)
			}
		}
	}()
	tasks := newUdpTaskPool(func(work udpPacketWork, slot *udpWriteSlot, data []byte) { work.execute(slot, data) })
	defer tasks.close()
	endpoints := new(UdpEndpointPool)
	defer endpoints.closeAll()
	plane := &ControlPlane{ctx: ctx, udpTaskPool: tasks, udpEndpoints: endpoints}

	start := time.Now()
	from, to := start.Add(warmup), start.Add(warmup+duration)
	rec := &qexpRecorder{from: from.UnixNano(), to: to.UnixNano(), samples: make(map[string][]float64), late: make(map[string]int)}
	stopped := make(chan struct{})
	// Probes go on after the window, unrecorded, and so does the load until
	// each probe stream settles: once a probe sent after the window is
	// answered, every window probe ahead of it was answered or lost under
	// load, not after it stopped.
	var settled []*atomic.Bool
	settle := func() *atomic.Bool {
		s := new(atomic.Bool)
		settled = append(settled, s)
		return s
	}
	var workers sync.WaitGroup
	ms := func(ns int64) float64 { return float64(ns) / 1e6 }

	var lanPort atomic.Uint32
	lanPort.Store(40000)
	openFlow := func(port int) *qexpFlow {
		flow := &qexpFlow{src: netip.AddrPortFrom(netip.MustParseAddr("192.168.77.10"), uint16(lanPort.Add(1))), dst: qexpAddr(host, port), replies: make(chan []byte, 1024)}
		// Setup is skipped: the dial gets none of the context setup would
		// give it, such as the sniffed protocol.
		conn, err := mux.ListenPacket(ctx, flow.dst.String())
		if err != nil {
			t.Fatal(err)
		}
		ue := &UdpEndpoint{conn: conn, NatTimeout: time.Hour, replies: flow}
		endpoints.add(flow.src, ue)
		ue.startSocket(endpoints, flow.src, flow.dst, netip.AddrPort{}, conn)
		return flow
	}
	dial := func(port int) net.Conn {
		conn, err := mux.DialContext(ctx, "tcp", qexpAddr(host, port).String())
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	every := func(interval time.Duration, tick func()) {
		workers.Go(func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-stopped:
					return
				case <-ticker.C:
					tick()
				}
			}
		})
	}
	drops := func() map[string]uint64 {
		counts := make(map[string]uint64)
		for drop := range netproxy.Drops() {
			counts[drop.Direction()+"/"+drop.Reason()] = drop.Load()
		}
		return counts
	}
	// From before the first UDP flow, as the flows' sent counts.
	dropsBefore := drops()
	// counters are read at the window's edges; reported holds the final
	// counts of the UDP flows.
	counters := make(map[string][]*qexpCounter)
	upload := func(name string, conn io.ReadWriter) {
		counter := new(qexpCounter)
		counters[name] = append(counters[name], counter)
		go counter.follow(conn)
		workers.Go(func() {
			buf := make([]byte, qexpChunk)
			for {
				select {
				case <-stopped:
					return
				default:
				}
				if _, err := conn.Write(buf); err != nil {
					return
				}
			}
		})
	}

	// TCP first: a UDP flow then joins carriers TCP already loads.
	for range workload["bulk"] {
		conn := dial(qexpBulkPort)
		defer conn.Close()
		upload("bulk", conn)
	}
	if workload["itcp"] > 0 {
		conn := dial(qexpInteractivePort)
		defer conn.Close()
		answered := settle()
		var seq uint32
		every(qexpProbeInterval, func() {
			seq++
			record := make([]byte, qexpProbeSize)
			binary.BigEndian.PutUint32(record, seq)
			binary.BigEndian.PutUint64(record[4:], uint64(qexpNow()))
			_, _ = conn.Write(record)
		})
		go func() {
			reply := make([]byte, 20)
			for {
				if _, err := io.ReadFull(conn, reply); err != nil {
					return
				}
				sentAt := int64(binary.BigEndian.Uint64(reply[4:]))
				rec.add("itcp_up_ms", sentAt, ms(int64(binary.BigEndian.Uint64(reply[12:]))-sentAt))
				if sentAt >= rec.to {
					answered.Store(true)
				}
			}
		}()
	}
	var download net.Conn
	if mode := qexpEnv(t, "QEXP_DOWNLOAD", ""); mode != "" {
		conn := dial(qexpDownloadPort)
		download = conn
		defer conn.Close()
		if _, err := conn.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		workers.Go(func() {
			buf := make([]byte, qexpChunk)
			for i := 0; ; i++ {
				select {
				case <-stopped:
					return
				default:
				}
				switch mode {
				case "stall": // read for 2 s, then stop reading for 2 s
					if i%2 == 1 {
						time.Sleep(2 * time.Second)
						continue
					}
					_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					for {
						if _, err := conn.Read(buf); err != nil {
							break
						}
					}
				case "slow": // 1 MiB/s
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					time.Sleep(time.Second * qexpChunk / (1 << 20))
				}
			}
		})
	}
	time.Sleep(500 * time.Millisecond)

	var game, flood *qexpFlow
	var windowProbes atomic.Uint64 // sent inside the window
	if workload["game"] > 0 {
		game = openFlow(qexpGamePort)
		var seq uint32
		every(qexpProbeInterval, func() {
			seq++
			probe := make([]byte, qexpProbeSize)
			probe[0] = 'P'
			binary.BigEndian.PutUint32(probe[1:], seq)
			now := qexpNow()
			binary.BigEndian.PutUint64(probe[5:], uint64(now))
			if now >= rec.from && now < rec.to {
				windowProbes.Add(1)
			}
			game.sent.Add(1)
			plane.enqueueUDPPacket(probe, game.src, game.dst, nil)
		})
	}
	if rate := workload["flood"]; rate > 0 {
		flood = openFlow(qexpFloodPort)
		const size = 1200
		interval := time.Duration(float64(time.Second) * size * 8 / (float64(rate) * 1e6))
		workers.Go(func() {
			packet := bytes.Repeat([]byte{'F'}, size)
			next := time.Now()
			for {
				select {
				case <-stopped:
					return
				default:
				}
				next = next.Add(interval)
				time.Sleep(time.Until(next))
				flood.sent.Add(1)
				plane.enqueueUDPPacket(packet, flood.src, flood.dst, nil)
			}
		})
	}
	var quicClient *quic.Conn
	if workload["quic"] > 0 {
		flow := openFlow(qexpQUICPort)
		lan := &qexpLANConn{plane: plane, flow: flow, closed: make(chan struct{})}
		defer lan.Close()
		quicClient, err = quic.Dial(ctx, lan, net.UDPAddrFromAddrPort(flow.dst), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"qexp"}}, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer quicClient.CloseWithError(0, "")
		stream, err := quicClient.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		upload("quic", stream)
	}
	if workload["ttfb"] > 0 {
		answered := settle()
		every(500*time.Millisecond, func() {
			began := qexpNow()
			if began >= rec.to { // the window's attempts, earlier ticks, are done
				answered.Store(true)
				return
			}
			conn, err := mux.DialContext(ctx, "tcp", qexpAddr(host, qexpTTFBPort).String())
			if err != nil {
				return
			}
			defer conn.Close()
			b := []byte{1}
			if _, err := conn.Write(b); err == nil {
				if _, err := conn.Read(b); err == nil {
					rec.add("ttfb_ms", began, ms(qexpNow()-began))
				}
			}
		})
	}
	reported := make(map[*qexpFlow]*atomic.Uint64)
	for _, flow := range []*qexpFlow{game, flood} {
		if flow == nil {
			continue
		}
		count := new(atomic.Uint64)
		reported[flow] = count
		var answered *atomic.Bool
		if flow == game {
			answered = settle()
		}
		go func() {
			for reply := range flow.replies {
				switch {
				case reply[0] == 'R' && len(reply) >= 9:
					count.Store(binary.BigEndian.Uint64(reply[1:]))
				case reply[0] == 'P' && len(reply) >= 29:
					sentAt, receivedAt := int64(binary.BigEndian.Uint64(reply[5:])), int64(binary.BigEndian.Uint64(reply[13:]))
					count.Store(max(count.Load(), binary.BigEndian.Uint64(reply[21:])))
					flow.echoed.Add(1)
					rec.add("game_up_ms", sentAt, ms(receivedAt-sentAt))
					rec.add("game_down_ms", sentAt, ms(qexpNow()-receivedAt-returnDelay.Nanoseconds()))
					if sentAt >= rec.to {
						answered.Store(true)
					}
				}
			}
		}()
	}
	// The fullest carrier: idle ones would dilute its percentiles.
	every(10*time.Millisecond, func() {
		if samples := carriers.notsent(); len(samples) > 0 {
			rec.add("notsent_bytes", qexpNow(), slices.Max(samples))
		}
	})

	cpu := func() time.Duration {
		var usage unix.Rusage
		if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
			t.Fatal(err)
		}
		return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
	}
	time.Sleep(time.Until(from))
	cpuFrom := cpu()
	for _, list := range counters {
		for _, c := range list {
			c.first.Store(c.latest.Load())
		}
	}
	time.Sleep(time.Until(to))
	cpuUsed := cpu() - cpuFrom
	for _, list := range counters {
		for _, c := range list {
			c.last.Store(c.latest.Load())
		}
	}
	// Bounded: a stream whose later probes are all lost never settles.
	for limit := time.Now().Add(duration); time.Now().Before(limit) &&
		slices.ContainsFunc(settled, func(s *atomic.Bool) bool { return !s.Load() }); {
		time.Sleep(qexpProbeInterval)
	}
	rec.stopped.Store(qexpNow())
	close(stopped)
	workers.Wait()
	if download != nil {
		// Its unread data would hold up the final counts.
		_ = download.Close()
	}
	// Let queues drain, then ask the reflectors for their final counts.
	time.Sleep(time.Second)
	for flow := range reported {
		for range 5 {
			plane.enqueueUDPPacket([]byte{'R'}, flow.src, flow.dst, nil)
			time.Sleep(200 * time.Millisecond)
		}
	}

	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"elapsed_s": time.Since(start).Seconds(), "settle_s": time.Duration(rec.stopped.Load() - rec.to).Seconds(),
		"carriers": len(carriers.notsent()), "datagram_memory_peak": udpPacketMemory.Status().Peak, "maxrss_kb": usage.Maxrss,
	}
	for _, name := range []string{"WORKLOAD", "MAX_CONNECTIONS", "WRITER_DELAY", "MPTCP", "DOWNLOAD", "RETURN_DELAY", "LABEL", "BINARY"} {
		report[strings.ToLower(name)] = os.Getenv("QEXP_" + name)
	}
	rec.mu.Lock()
	for name, samples := range rec.samples {
		report[name] = qexpSummary(samples)
	}
	report["late"] = rec.late
	windowEchoed := len(rec.samples["game_up_ms"])
	rec.mu.Unlock()
	var uploaded float64
	for name, list := range counters {
		var total, squares float64
		flows := make([]float64, 0, len(list))
		for _, c := range list {
			rate := c.mbit(duration)
			flows = append(flows, rate)
			total, squares = total+rate, squares+rate*rate
		}
		report[name+"_mbit"] = total
		report[name+"_flows_mbit"] = flows
		if squares > 0 {
			report[name+"_jain"] = total * total / (float64(len(list)) * squares)
		}
		uploaded += total * duration.Seconds() / 8 * 1e6
	}
	if bulk, ok := report["bulk_mbit"].(float64); ok {
		if quicRate, ok := report["quic_mbit"].(float64); ok && bulk+quicRate > 0 {
			report["quic_share"] = quicRate / (bulk + quicRate)
		}
	}
	// The process also runs the LAN's QUIC client and the writer's spin.
	if uploaded > 0 && workload["quic"] == 0 && writerDelay == 0 {
		report["cpu_ms_per_gb"] = float64(cpuUsed.Milliseconds()) / (uploaded / 1e9)
	}
	var lostUpload, lostDownload int64
	for flow, count := range reported {
		name := "game"
		if flow == flood {
			name = "flood"
		}
		sent, received := flow.sent.Load(), count.Load()
		report[name+"_sent"], report[name+"_received"] = sent, received
		report[name+"_lost"] = int64(sent) - int64(received)
		lostUpload += int64(sent) - int64(received)
		if name == "game" {
			echoed := flow.echoed.Load()
			report["game_echoed"], report["game_lan_dropped"] = echoed, flow.dropped.Load()
			lostDownload += int64(received) - int64(echoed) - int64(flow.dropped.Load())
			report["game_window_unechoed"] = int64(windowProbes.Load()) - int64(windowEchoed)
		}
	}
	counted := make(map[string]uint64)
	totals := make(map[string]int64)
	for key, n := range drops() {
		if n -= dropsBefore[key]; n > 0 {
			counted[key] = n
			direction, _, _ := strings.Cut(key, "/")
			totals[direction] += int64(n)
		}
	}
	report["drops"], report["drops_upload"], report["drops_download"] = counted, totals[netproxy.DropUpload], totals[netproxy.DropDownload]
	// Lost probes not matched by drop counters. A LAN QUIC flow's drops are
	// counted too, but its datagrams are not, so it has no check.
	if workload["quic"] == 0 {
		report["upload_unaccounted"] = lostUpload - totals[netproxy.DropUpload]
		report["download_unaccounted"] = lostDownload - totals[netproxy.DropDownload]
	}
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("QEXP_OUT"); path != "" {
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(out))
}
