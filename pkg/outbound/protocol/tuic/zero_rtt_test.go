package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/quic-go"
)

// heldPacketParent can hold every packet its next connection receives, so
// the client's 0-RTT data leaves while the handshake cannot complete.
type heldPacketParent struct {
	loopbackPacketParent
	wait    <-chan struct{}
	release func()
}

// hold applies to the next ListenPacket and returns its release.
func (p *heldPacketParent) hold() func() {
	wait := make(chan struct{})
	p.wait, p.release = wait, sync.OnceFunc(func() { close(wait) })
	return p.release
}

func (p *heldPacketParent) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	conn, err := p.loopbackPacketParent.ListenPacket(ctx, address)
	if err != nil || p.wait == nil {
		return conn, err
	}
	held := &heldPacketConn{PacketConn: conn, wait: p.wait, release: p.release}
	p.wait, p.release = nil, nil
	return held, nil
}

type heldPacketConn struct {
	net.PacketConn
	wait    <-chan struct{}
	release func()
}

func (c *heldPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	<-c.wait
	return c.PacketConn.ReadFrom(b)
}

// Transport.Close ends its read loop with a read deadline.
func (c *heldPacketConn) SetReadDeadline(t time.Time) error {
	c.release()
	return c.PacketConn.SetReadDeadline(t)
}

// ticketCache reports the session tickets the client stores.
type ticketCache struct {
	tls.ClientSessionCache
	stored chan struct{}
}

func newTicketCache() *ticketCache {
	return &ticketCache{ClientSessionCache: tls.NewLRUClientSessionCache(1), stored: make(chan struct{}, 1)}
}

func (c *ticketCache) Put(key string, session *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, session)
	if session != nil {
		select {
		case c.stored <- struct{}{}:
		default:
		}
	}
}

func (c *ticketCache) wait(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-c.stored:
	case <-ctx.Done():
		t.Fatal("no session ticket stored")
	}
}

// newReduceRttDialer opts into 0-RTT. Every peer shares the session cache
// key 127.0.0.1, the server name quic-go infers.
func newReduceRttDialer(t *testing.T, parent netproxy.Dialer, address string, cache tls.ClientSessionCache, flags protocol.Flags) *Dialer {
	t.Helper()
	d, err := NewDialer(parent, protocol.Header{ProxyAddress: address, User: "00000000-0000-0000-0000-000000000000", Password: "test", Feature1: "bbr", Flags: protocol.Flags_Tuic_ReduceRtt | flags, TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"tuic-test"}, ClientSessionCache: cache}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func ringMember(t *testing.T, ctx context.Context, d *Dialer) *clientImpl {
	t.Helper()
	var member *clientImpl
	if err := d.clientRing.Allocate(ctx, false, func(_ context.Context, c *clientImpl) error { member = c; return nil }); err != nil {
		t.Fatal(err)
	}
	return member
}

// acceptPeer leaves before the dialer closes, which then waits for no stream.
func acceptPeer(t *testing.T, ctx context.Context, listener interface {
	Accept(context.Context) (*quic.Conn, error)
}) *quic.Conn {
	t.Helper()
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })
	return server
}

// readAuthentication verifies the token as a server does, with the exporter
// of its side of the completed handshake.
func readAuthentication(t *testing.T, ctx context.Context, server *quic.Conn) {
	t.Helper()
	stream, err := server.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2+16+32)
	if _, err := io.ReadFull(stream, frame); err != nil {
		t.Fatal(err)
	}
	state := server.ConnectionState().TLS
	token, err := state.ExportKeyingMaterial(string(frame[2:18]), []byte("test"), 32)
	if err != nil || frame[0] != Ver5 || frame[1] != AuthenticateType || !bytes.Equal(frame[18:], token) {
		t.Fatalf("authentication %x, exporter error %v", frame, err)
	}
}

func readRequest(t *testing.T, stream io.Reader, payload string) {
	t.Helper()
	if addr, err := readConnectFixture(stream); err != nil || addr.String() != "example.test:443" {
		t.Fatalf("CONNECT=%v err=%v", addr, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != payload {
		t.Fatalf("payload=%q err=%v", got, err)
	}
}

// Without a ticket the dial completes the handshake first. A reconnect
// resuming a session that allows early data sends CONNECT with the first
// payload in 0-RTT and authenticates once the handshake completes.
func TestReduceRttReconnectSendsRequestIn0RTT(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	listener, err := quic.ListenAddrEarly("127.0.0.1:0", recoveryTLS(t), &quic.Config{EnableDatagrams: true, Allow0RTT: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	cache := newTicketCache()
	parent := &heldPacketParent{}
	d := newReduceRttDialer(t, parent, listener.Addr().String(), cache, 0)

	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	first := ringMember(t, ctx, d)
	if !handshakeComplete(first.quicConn) {
		t.Fatal("dial without a ticket returned before the handshake")
	}
	readAuthentication(t, ctx, acceptPeer(t, ctx, listener))
	cache.wait(t, ctx)
	first.failConnection(errors.New("reconnect"))

	release := parent.hold()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	second := ringMember(t, ctx, d)
	if handshakeComplete(second.quicConn) {
		t.Fatal("0-RTT dial waited for the handshake")
	}
	client, err := d.DialContext(ctx, "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	wrote := make(chan error, 1)
	go func() { _, err := client.Write([]byte("hello")); wrote <- err }()
	server := acceptPeer(t, ctx, listener)
	// The client receives nothing yet, so the request arrived in 0-RTT.
	remote, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readRequest(t, remote, "hello")
	release()
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	readAuthentication(t, ctx, server)
	if !second.quicConn.ConnectionState().Used0RTT || !server.ConnectionState().Used0RTT {
		t.Fatal("0-RTT not accepted")
	}
	if _, err := remote.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
}

// rejectingListener rejects 0-RTT for the early-data ticket in cache, which
// a server sharing its certificate issued.
func rejectingListener(t *testing.T, ctx context.Context) (*quic.Listener, *ticketCache) {
	t.Helper()
	serverTLS := recoveryTLS(t)
	accepting, err := quic.ListenAddrEarly("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true, Allow0RTT: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepting.Close() })
	rejecting, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rejecting.Close() })
	cache := newTicketCache()
	issuer := newReduceRttDialer(t, loopbackPacketParent{}, accepting.Addr().String(), cache, 0)
	if err := issuer.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	acceptPeer(t, ctx, accepting)
	cache.wait(t, ctx)
	return rejecting, cache
}

// A server rejecting 0-RTT discards the early stream unread. The request is
// resent once on a 1-RTT stream, a concurrent read moves to that stream, and
// the session authenticates and stays connected.
func TestReduceRttRejectionResendsRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	rejecting, cache := rejectingListener(t, ctx)
	parent := &heldPacketParent{}
	d := newReduceRttDialer(t, parent, rejecting.Addr().String(), cache, 0)
	release := parent.hold()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	member := ringMember(t, ctx, d)
	if handshakeComplete(member.quicConn) {
		t.Fatal("0-RTT dial waited for the handshake")
	}
	client, err := d.DialContext(ctx, "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	wrote := make(chan error, 1)
	go func() { _, err := client.Write([]byte("hello")); wrote <- err }()
	// Read while the first write holds the command lock, so the read waits
	// on the early stream.
	conn := client.(*connectConn)
	for conn.first.TryLock() {
		conn.first.Unlock()
		time.Sleep(time.Millisecond)
	}
	read := make(chan error, 1)
	reply := make([]byte, 4)
	go func() { _, err := io.ReadFull(client, reply); read <- err }()
	// The replacement stream inherits the deadline.
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	release()

	server := acceptPeer(t, ctx, rejecting)
	readAuthentication(t, ctx, server)
	remote, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readRequest(t, remote, "hello")
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil || string(reply) != "pong" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if _, err := client.Read(reply); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the deadline: %v", err)
	}
	if member.quicConn.ConnectionState().Used0RTT || server.ConnectionState().Used0RTT {
		t.Fatal("0-RTT accepted")
	}
	idle, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	if _, err := server.AcceptStream(idle); err == nil {
		t.Fatal("request sent twice")
	}
	if d.Snapshot().State != netproxy.SessionConnected || !member.lease.Valid() {
		t.Fatalf("rejection failed the session: %+v", d.Snapshot())
	}
	// A dial can see the handshake incomplete yet open its stream after the
	// rejection, on the 1-RTT connection, which carries the write once.
	later, err := d.DialContext(ctx, "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = later.Close() })
	c := later.(*connectConn)
	c.trackedStream = newEarlyStream(c.trackedStream.(interface{ Context() context.Context }).Context(), member.quicConn, c.trackedStream, func() (trackedStream, error) {
		return nil, errors.New("reopened a 1-RTT stream")
	}, func(err error, _ netproxy.Operation) error { return err })
	if _, err := later.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	remote, err = server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readRequest(t, remote, "again")
}

// In QUIC relay mode, a packet whose write is still blocked on its 0-RTT
// stream when the server rejects early data is lost like any UDP packet, and
// the session stays connected.
func TestReduceRttRejectionDropsBlockedPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	rejecting, cache := rejectingListener(t, ctx)
	parent := &heldPacketParent{}
	d := newReduceRttDialer(t, parent, rejecting.Addr().String(), cache, protocol.Flags_Tuic_UdpRelayModeQuic)
	release := parent.hold()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	member := ringMember(t, ctx, d)
	udp, err := d.ListenPacket(ctx, "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	var sent atomic.Int32
	wrote := make(chan error, 1)
	go func() {
		payload := make([]byte, 4000)
		for range 64 {
			if _, err := udp.WriteTo(payload, netproxy.NewAddr("udp", "127.0.0.1:53")); err != nil {
				wrote <- err
				return
			}
			sent.Add(1)
		}
		wrote <- nil
	}()
	// Without acknowledgements, a write soon blocks on the congestion window.
	pc := udp.(*quicStreamPacketConn)
	for last := int32(-1); ; last = sent.Load() {
		time.Sleep(20 * time.Millisecond)
		pc.stateMu.Lock()
		blocked := pc.sendStream != nil && sent.Load() == last
		pc.stateMu.Unlock()
		if blocked {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("no packet write blocked")
		}
	}
	release()
	acceptPeer(t, ctx, rejecting)
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if member.quicConn.ConnectionState().Used0RTT {
		t.Fatal("0-RTT accepted")
	}
	if d.Snapshot().State != netproxy.SessionConnected || !member.lease.Valid() {
		t.Fatalf("rejection failed the session: %+v", d.Snapshot())
	}
}

// A fresh ticket key and a certificate flight larger than one datagram separate
// the 0-RTT rejection from Finished, without delaying the server's TLS worker.
func TestReduceRttRejectionWindowAdmitsDials(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	_, cache := rejectingListener(t, ctx)
	serverTLS := recoveryTLS(t)
	cert := &serverTLS.Certificates[0]
	for range 24 {
		cert.Certificate = append(cert.Certificate, cert.Certificate[0])
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	steps := make(chan struct{})
	release := sync.OnceFunc(func() { close(steps) })
	parent := &heldPacketParent{wait: steps, release: release}
	d := newReduceRttDialer(t, parent, listener.Addr().String(), cache, 0)
	t.Cleanup(release)
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	member := ringMember(t, ctx, d)
	probe, err := member.quicConn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	for !errors.Is(context.Cause(probe.Context()), quic.Err0RTTRejected) {
		if handshakeComplete(member.quicConn) {
			t.Fatal("missed rejection window")
		}
		select {
		case steps <- struct{}{}:
		case <-ctx.Done():
			t.Fatal("server sent no handshake packet")
		}
		select {
		case <-probe.Context().Done():
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("server did not reject early data")
		}
	}
	if handshakeComplete(member.quicConn) {
		t.Fatal("rejection and Finished arrived in the same datagram")
	}
	// OpenStream synchronizes with ResetFor0RTT, including its credit callback.
	if _, err := member.quicConn.OpenStream(); !errors.Is(err, quic.Err0RTTRejected) {
		t.Fatalf("stream during rejection: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		conn, err := d.DialContext(ctx, "tcp", "example.test:443")
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("dial did not wait for rejected handshake: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if snapshot := d.Snapshot(); snapshot.RecoveryRequired {
		t.Fatalf("rejection requested another member: %+v", snapshot)
	}
	release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("dial did not finish after rejection")
	}
	readAuthentication(t, ctx, acceptPeer(t, ctx, listener))
	if snapshot := d.Snapshot(); snapshot.RecoveryRequired || snapshot.State != netproxy.SessionConnected {
		t.Fatalf("rejection changed readiness: %+v", snapshot)
	}
}

// TUIC v5 reads only the header of non-auth commands until authentication.
func holdCommandsUntilAuthentication(ctx context.Context, server *quic.Conn) (<-chan error, <-chan struct{}) {
	result := make(chan error, 1)
	held := make(chan struct{}, 128)
	authenticated := make(chan struct{})
	go func() {
		for {
			stream, err := server.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer stream.CancelRead(0)
				deadline, _ := ctx.Deadline()
				_ = stream.SetReadDeadline(deadline)
				var head [2]byte
				if _, err := io.ReadFull(stream, head[:]); err != nil {
					return
				}
				if head != [2]byte{Ver5, AuthenticateType} {
					select {
					case held <- struct{}{}:
					default:
					}
					select {
					case <-authenticated:
					case <-ctx.Done():
						return
					}
					_, _ = io.Copy(io.Discard, stream)
					return
				}
				var frame [48]byte
				_, err := io.ReadFull(stream, frame[:])
				if err == nil {
					state := server.ConnectionState().TLS
					var token []byte
					token, err = state.ExportKeyingMaterial(string(frame[:16]), []byte("test"), 32)
					if err == nil && (!bytes.Equal(frame[16:], token) || stream.StreamID() != 2) {
						err = errors.New("authentication did not use the reserved stream and valid exporter")
					}
				}
				result <- err
				close(authenticated)
			}()
		}
	}()
	return result, held
}

func TestReduceRttReservesAuthenticationCredit(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "rejected"}[reject], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			t.Cleanup(cancel)
			serverTLS := recoveryTLS(t)
			issuer, err := quic.ListenAddrEarly("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true, Allow0RTT: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = issuer.Close() })
			cache := newTicketCache()
			first := newReduceRttDialer(t, loopbackPacketParent{}, issuer.Addr().String(), cache, 0)
			if err := first.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			readAuthentication(t, ctx, acceptPeer(t, ctx, issuer))
			cache.wait(t, ctx)
			listener := issuer
			if reject {
				listener, err = quic.ListenAddrEarly("127.0.0.1:0", recoveryTLS(t), &quic.Config{EnableDatagrams: true, Allow0RTT: true})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
			}
			parent := &heldPacketParent{}
			release := parent.hold()
			d := newReduceRttDialer(t, parent, listener.Addr().String(), cache, protocol.Flags_Tuic_UdpRelayModeQuic)
			t.Cleanup(release)
			if err := d.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			member := ringMember(t, ctx, d)
			udp, err := d.ListenPacket(ctx, "127.0.0.1:53")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = udp.Close() })
			addr := netproxy.NewAddr("udp", "127.0.0.1:53")
			before := netproxy.DropCarrierQueueFull.Load()
			for i := range 110 {
				if n, err := udp.WriteTo([]byte{1}, addr); n != 1 || err != nil {
					t.Errorf("early packet %d: %d, %v", i, n, err)
				}
			}
			if dropped := netproxy.DropCarrierQueueFull.Load() - before; dropped != 11 {
				t.Errorf("dropped %d packets, want 11 with one reserved stream", dropped)
			}
			if handshakeComplete(member.quicConn) {
				t.Fatal("packets were not sent during 0-RTT")
			}
			server := acceptPeer(t, ctx, listener)
			authenticated, held := holdCommandsUntilAuthentication(ctx, server)
			if !reject {
				for range 99 {
					select {
					case <-held:
					case <-ctx.Done():
						t.Fatal("early packets did not arrive before authentication")
					}
				}
			}
			start := member.quicConn.HandshakeComplete()
			if reject {
				probe, err := member.quicConn.OpenStream()
				if err != nil {
					t.Fatal(err)
				}
				start = probe.Context().Done()
			}
			var writers sync.WaitGroup
			t.Cleanup(func() { cancel(); writers.Wait() })
			for range 8 {
				packet, err := d.ListenPacket(ctx, "127.0.0.1:53")
				if err != nil {
					t.Fatal(err)
				}
				writers.Go(func() {
					defer packet.Close()
					select {
					case <-start:
					case <-ctx.Done():
						return
					}
					for range 20 {
						if _, err := packet.WriteTo([]byte{2}, addr); err != nil {
							t.Errorf("packet across handshake: %v", err)
							return
						}
					}
				})
			}
			release()
			select {
			case err := <-authenticated:
				if err != nil {
					t.Fatal(err)
				}
			case <-member.lease.Done():
				t.Fatalf("authentication failed the member: %v", member.lease.Cause())
			case <-ctx.Done():
				t.Fatal("authentication was starved of uni-stream credit")
			}
			writers.Wait()
			if snapshot := d.Snapshot(); snapshot.State != netproxy.SessionConnected || snapshot.RecoveryRequired || !member.lease.Valid() {
				t.Fatalf("packet pressure changed readiness: %+v", snapshot)
			}
			if server.ConnectionState().Used0RTT == reject {
				t.Fatalf("unexpected early-data outcome: rejected=%v", reject)
			}
		})
	}
}

func TestReduceRttEarlyStreamReservationStillApplies(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		t.Run(map[bool]string{false: "reservation", true: "exhausted"}[exhausted], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			t.Cleanup(cancel)
			listener, err := quic.ListenAddrEarly("127.0.0.1:0", recoveryTLS(t), &quic.Config{EnableDatagrams: true, Allow0RTT: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			cache := newTicketCache()
			parent := &heldPacketParent{}
			d := newReduceRttDialer(t, parent, listener.Addr().String(), cache, 0)
			if err := d.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			readAuthentication(t, ctx, acceptPeer(t, ctx, listener))
			cache.wait(t, ctx)
			ringMember(t, ctx, d).failConnection(errors.New("reconnect"))
			release := parent.hold()
			t.Cleanup(release)
			if err := d.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			member := ringMember(t, ctx, d)
			if exhausted {
				// Concurrent opens can consume the remaining credit past the ring's
				// reservation check. Exercise QUIC's actual stream-limit error.
				for range 100 {
					if _, err := member.quicConn.OpenStream(); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				for range 90 {
					stream, err := d.DialContext(ctx, "tcp", "example.test:443")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = stream.Close() })
				}
			}
			if _, err := d.DialContext(ctx, "tcp", "example.test:443"); netproxy.ClassifyFailure(err).Reason != netproxy.ReasonCapacity {
				t.Fatalf("early stream limit: %v", err)
			}
			if snapshot := d.Snapshot(); !snapshot.RecoveryRequired || snapshot.State != netproxy.SessionConnected {
				t.Fatalf("real exhaustion did not request capacity: %+v", snapshot)
			}
			release()
			readAuthentication(t, ctx, acceptPeer(t, ctx, listener))
		})
	}
}
