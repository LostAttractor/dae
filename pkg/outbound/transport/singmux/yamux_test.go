package singmux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
	yamux "github.com/libp2p/go-yamux/v5"
)

// muxRequest is what a sing-mux server reads before serving a stream.
type muxRequest struct {
	flags       uint16
	destination string
}

// serveSingMux is a minimal sing-mux server: it checks the session header,
// then answers every stream request with success and hands the stream to
// handle. It speaks yamux through the same library as the client.
func serveSingMux(t *testing.T, protocol Protocol, handle func(muxRequest, net.Conn)) *pipeDialer {
	t.Helper()
	parent := &pipeDialer{server: make(chan net.Conn)}
	served := make(chan struct{})
	go func() {
		defer close(served)
		for conn := range parent.server {
			header := make([]byte, 2)
			if _, err := io.ReadFull(conn, header); err != nil || header[0] != Version0 || header[1] != byte(protocol) {
				t.Errorf("session header = %v, %v", header, err)
				_ = conn.Close()
				continue
			}
			go serveStreams(t, protocol, conn, handle)
		}
	}()
	t.Cleanup(func() {
		close(parent.server)
		<-served
	})
	return parent
}

func serveStreams(t *testing.T, protocol Protocol, conn net.Conn, handle func(muxRequest, net.Conn)) {
	accept := func() (net.Conn, error) { return nil, net.ErrClosed }
	switch protocol {
	case ProtocolYAMux:
		config := yamux.DefaultConfig()
		config.LogOutput = io.Discard
		session, err := yamux.Server(conn, config, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer session.Close()
		accept = session.Accept
	case ProtocolSmux:
		session := smuxtest.Server(conn)
		defer session.Close()
		accept = func() (net.Conn, error) { return session.Accept() }
	}
	for {
		stream, err := accept()
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			var request muxRequest
			if err := binary.Read(stream, binary.BigEndian, &request.flags); err != nil {
				return
			}
			addr, err := socks5.ReadAddr(stream)
			if err != nil {
				return
			}
			request.destination = addr.String()
			if _, err := stream.Write([]byte{0}); err != nil {
				return
			}
			handle(request, stream)
		}()
	}
}

func newTestMux(t *testing.T, protocol Protocol, handle func(muxRequest, net.Conn)) *Mux {
	t.Helper()
	mux := &Mux{Dialer: serveSingMux(t, protocol, handle), Protocol: protocol, MaxConnections: 1}
	t.Cleanup(func() { _ = mux.Close() })
	if err := mux.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	return mux
}

func TestYamuxStreamRoundTrip(t *testing.T) {
	requests := make(chan muxRequest, 1)
	mux := newTestMux(t, ProtocolYAMux, func(request muxRequest, stream net.Conn) {
		requests <- request
		_, _ = io.Copy(stream, stream)
	})
	conn, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "hello" {
		t.Fatalf("echo = %q, %v", reply, err)
	}
	if request := <-requests; request.flags != 0 || request.destination != "target.example:443" {
		t.Fatalf("stream request = %+v", request)
	}
	if state := mux.Snapshot(); !state.Accepting || state.Layer != netproxy.LayerYAMUX {
		t.Fatalf("pool state = %+v", state)
	}
}

// CloseWrite ends only the upload: the server reads EOF and its reply still
// arrives. Before any Write, it sends the stream request first.
func TestYamuxCloseWriteHalfCloses(t *testing.T) {
	for _, upload := range []string{"request", ""} {
		requests := make(chan muxRequest, 1)
		mux := newTestMux(t, ProtocolYAMux, func(request muxRequest, stream net.Conn) {
			requests <- request
			data, err := io.ReadAll(stream)
			if err == nil {
				_, _ = stream.Write(append([]byte("reply:"), data...))
			}
		})
		conn, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if upload != "" {
			if _, err := conn.Write([]byte(upload)); err != nil {
				t.Fatal(err)
			}
		}
		if err := netproxy.CloseWrite(conn); err != nil {
			t.Fatal(err)
		}
		if reply, err := io.ReadAll(conn); err != nil || string(reply) != "reply:"+upload {
			t.Fatalf("reply = %q, %v", reply, err)
		}
		if request := <-requests; request.destination != "target.example:443" {
			t.Fatalf("stream request = %+v", request)
		}
	}
}

func TestYamuxCarriesUDP(t *testing.T) {
	requests := make(chan muxRequest, 1)
	mux := newTestMux(t, ProtocolYAMux, func(request muxRequest, stream net.Conn) {
		requests <- request
		// Echo packet-addressed datagrams: address, length, payload.
		for {
			addr, err := socks5.ReadAddr(stream)
			if err != nil {
				return
			}
			var length uint16
			if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
				return
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(stream, payload); err != nil {
				return
			}
			var reply bytes.Buffer
			_ = socks5.WriteNetAddr(addr, &reply)
			_ = binary.Write(&reply, binary.BigEndian, length)
			reply.Write(payload)
			if _, err := stream.Write(reply.Bytes()); err != nil {
				return
			}
		}
	})
	conn, err := mux.ListenPacket(t.Context(), "dns.example:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	target := netproxy.NewAddr("udp", "192.0.2.1:53")
	for _, payload := range []string{"query", "second"} {
		if _, err := conn.WriteTo([]byte(payload), target); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, from, err := conn.ReadFrom(buf)
		if err != nil || string(buf[:n]) != payload || from.String() != "192.0.2.1:53" {
			t.Fatalf("datagram = %q from %v, %v", buf[:n], from, err)
		}
	}
	if request := <-requests; request.flags != flagUDP|flagAddr || request.destination != "dns.example:53" {
		t.Fatalf("UDP stream request = %+v", request)
	}
}

// A stream whose reader stalls must not hold back other streams of the
// session. smux v1 shares one receive buffer per session and does.
func TestStalledStreamDoesNotBlockSession(t *testing.T) {
	const payload = 1 << 20
	for _, tc := range []struct {
		protocol Protocol
		blocks   bool
	}{{ProtocolYAMux, false}, {ProtocolSmux, true}} {
		t.Run(tc.protocol.String(), func(t *testing.T) {
			stalled := make(chan struct{})
			mux := newTestMux(t, tc.protocol, func(request muxRequest, stream net.Conn) {
				switch request.destination {
				case "flood.example:80":
					close(stalled)
					chunk := make([]byte, 64<<10)
					for {
						if _, err := stream.Write(chunk); err != nil {
							return
						}
					}
				default:
					_, _ = stream.Write(make([]byte, payload))
					_, _ = io.Copy(io.Discard, stream)
				}
			})
			flood, err := mux.DialContext(t.Context(), "tcp", "flood.example:80")
			if err != nil {
				t.Fatal(err)
			}
			defer flood.Close()
			if _, err := flood.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
			<-stalled
			// Let the flood fill whatever the protocol buffers for it.
			time.Sleep(100 * time.Millisecond)

			other, err := mux.DialContext(t.Context(), "tcp", "other.example:80")
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			timeout := 5 * time.Second
			if tc.blocks {
				timeout = 300 * time.Millisecond
			}
			_ = other.SetDeadline(time.Now().Add(timeout))
			if _, err := other.Write([]byte{0}); err != nil && !tc.blocks {
				t.Fatal(err)
			}
			_, err = io.ReadFull(other, make([]byte, payload))
			if blocked := errors.Is(err, netproxy.ErrNotConnected) || netproxy.ClassifyFailure(err).Reason == netproxy.ReasonDeadline; blocked != tc.blocks || err != nil && !blocked {
				t.Fatalf("download behind a stalled stream: %v", err)
			}
		})
	}
}

// A closed stream must not leave a server blocked writing into it until the
// session ends: it is reset unless the peer has closed by netproxy.CloseLinger.
func TestYamuxClosedStreamReleasesServerWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		released := make(chan struct{})
		mux := newTestMux(t, ProtocolYAMux, func(_ muxRequest, stream net.Conn) {
			defer close(released)
			chunk := make([]byte, 32<<10)
			for {
				if _, err := stream.Write(chunk); err != nil {
					return
				}
			}
		})
		conn, err := mux.DialContext(t.Context(), "tcp", "flood.example:80")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, conn, 1<<20); err != nil {
			t.Fatal(err)
		}
		closed := time.Now()
		_ = conn.Close()
		select {
		case <-released:
		case <-time.After(2 * netproxy.CloseLinger):
			t.Fatal("server is still writing into the closed stream")
		}
		if waited := time.Since(closed); waited > netproxy.CloseLinger {
			t.Fatalf("server writer released %v after Close", waited)
		}
	})
}

// The relay's order when the target closes first, on a path retired at the
// same time: the client reads EOF, sends its last upload, half-closes and
// closes, and the session closes right after. yamux only queues the upload
// and the FIN; closing the session must write them first.
func TestYamuxSessionCloseWritesQueuedFrames(t *testing.T) {
	const size = 64 << 10
	for range 20 {
		got := make(chan error, 1)
		mux := &Mux{Dialer: serveSingMux(t, ProtocolYAMux, func(_ muxRequest, stream net.Conn) {
			if err := netproxy.CloseWrite(stream); err != nil {
				got <- err
				return
			}
			_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
			data, err := io.ReadAll(stream)
			if err == nil && len(data) != size {
				err = fmt.Errorf("server read %d of %d bytes", len(data), size)
			}
			got <- err
		}), Protocol: ProtocolYAMux, MaxConnections: 1}
		if err := mux.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		conn, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		// The first byte carries the stream request.
		if _, err := conn.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(make([]byte, size-1)); err != nil {
			t.Fatal(err)
		}
		if err := netproxy.CloseWrite(conn); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		_ = mux.Close()
		if err := <-got; err != nil {
			t.Fatal(err)
		}
	}
}

// Close waits until the carrier took the GoAway, then half-closes the
// carrier; a pipe cannot, so Close returns at once. A peer that reads the
// carrier but keeps the session after a GoAway, as hashicorp/yamux does,
// does not hold Close: Close sees the GoAway being written.
func TestYamuxCloseDetectsGoAway(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent := &pipeDialer{server: make(chan net.Conn)}
		go func() {
			for conn := range parent.server {
				go func() { _, _ = io.Copy(io.Discard, conn) }()
			}
		}()
		defer close(parent.server)
		mux := &Mux{Dialer: parent, Protocol: ProtocolYAMux, MaxConnections: 1}
		if err := mux.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = mux.Close()
		if waited := time.Since(start); waited != 0 {
			t.Fatalf("Close took %v", waited)
		}
	})
}

// Close wakes a blocked reader at once and reports it as local cleanup.
func TestYamuxCloseWakesReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mux := newTestMux(t, ProtocolYAMux, func(_ muxRequest, stream net.Conn) {
			_, _ = io.Copy(io.Discard, stream)
		})
		conn, err := mux.DialContext(t.Context(), "tcp", "idle.example:80")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		read := make(chan error, 1)
		go func() {
			_, err := conn.Read(make([]byte, 1))
			read <- err
		}()
		synctest.Wait()
		_ = conn.Close()
		synctest.Wait()
		select {
		case err := <-read:
			if failure := netproxy.ClassifyFailure(err); failure.Origin != netproxy.OriginLocalCleanup || failure.Scope != netproxy.ScopeStream {
				t.Fatalf("read woken by Close: %v (%+v)", err, failure)
			}
		default:
			t.Fatal("Close did not wake the reader")
		}
		if state := mux.Snapshot(); !state.Accepting || state.EpisodeID != 0 {
			t.Fatalf("closing a stream disturbed the session: %+v", state)
		}
	})
}

// yamuxFrame encodes a yamux frame header.
func yamuxFrame(version, kind byte, flags uint16, stream, length uint32) []byte {
	header := []byte{version, kind}
	header = binary.BigEndian.AppendUint16(header, flags)
	header = binary.BigEndian.AppendUint32(header, stream)
	return binary.BigEndian.AppendUint32(header, length)
}

func TestYamuxSessionCloseClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		frame    []byte
		abort    bool
		remote   bool
		code     uint32
		protocol bool
	}{
		{name: "local close"},
		{name: "local abort", abort: true},
		{name: "remote close", frame: yamuxFrame(0, 3, 0, 0, 0), remote: true},
		{name: "remote protocol error", frame: yamuxFrame(0, 3, 0, 0, 1), remote: true, code: 1},
		{name: "invalid version", frame: yamuxFrame(9, 0, 0, 0, 0), protocol: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, peer := net.Pipe()
				defer peer.Close()
				go func() { _, _ = io.Copy(io.Discard, peer) }()
				s, err := newSession(ProtocolYAMux, &monitoredConn{Conn: client})
				if err != nil {
					t.Fatal(err)
				}
				defer s.abort()
				if tc.frame != nil {
					if _, err := peer.Write(tc.frame); err != nil {
						t.Fatal(err)
					}
					<-s.CloseChan()
				} else if tc.abort {
					_ = s.abort()
				} else {
					_ = s.Close()
				}
				synctest.Wait()
				// Cleanup must not replace a remote or protocol failure.
				_ = s.abort()
				err = s.closeErr()
				if failure := netproxy.ClassifyFailure(err); (failure.Reason == netproxy.ReasonProtocol) != tc.protocol {
					t.Fatalf("close error = %v (%+v)", err, failure)
				}
				if tc.protocol {
					if !errors.Is(err, yamux.ErrInvalidVersion) {
						t.Fatalf("lost protocol error: %v", err)
					}
				} else if goAway, ok := errors.AsType[*yamux.GoAwayError](err); !ok || goAway.Remote != tc.remote || goAway.ErrorCode != tc.code {
					t.Fatalf("close error = %v, want remote=%v code=%d", err, tc.remote, tc.code)
				}
			})
		})
	}
}

func TestYamuxProtocolViolationClosesSession(t *testing.T) {
	const data, windowUpdate, flagSYN = 0, 1, 1
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"unknown version", yamuxFrame(9, data, 0, 0, 0)},
		// Data beyond the 256 KiB initial window of the client's stream 1.
		{"receive window exceeded", yamuxFrame(0, data, 0, 1, 16<<20)},
		// Servers open even stream IDs; odd ones are the client's.
		{"client stream ID", yamuxFrame(0, windowUpdate, flagSYN, 1, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := &pipeDialer{server: make(chan net.Conn)}
			server := make(chan net.Conn, 1)
			go func() {
				conn := <-parent.server
				_, _ = io.ReadFull(conn, make([]byte, 2))
				server <- conn
			}()
			mux := &Mux{Dialer: parent, Protocol: ProtocolYAMux}
			t.Cleanup(func() { _ = mux.Close() })
			if err := mux.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			conn := <-server
			defer conn.Close()
			go func() { _, _ = io.Copy(io.Discard, conn) }()
			stream, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, err := conn.Write(tc.frame); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for mux.Snapshot().Cause == nil && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			state := mux.Snapshot()
			failure := netproxy.ClassifyFailure(state.Cause)
			if state.State != netproxy.SessionDisconnected || failure.Reason != netproxy.ReasonProtocol || failure.Layer != netproxy.LayerYAMUX || failure.Scope != netproxy.ScopeSharedResource {
				t.Fatalf("state after protocol violation = %+v (%+v)", state, failure)
			}
		})
	}
}

func TestYamuxWindowGrowthIsBoundedPerSession(t *testing.T) {
	budget := new(windowBudget)
	first, second := &windowSpan{budget: budget}, &windowSpan{budget: budget}
	// Initial windows are always granted; growth shares the session budget.
	if err := first.ReserveMemory(256<<10, 255); err != nil {
		t.Fatal(err)
	}
	if err := first.ReserveMemory(yamuxSessionWindow-1<<20, 128); err != nil {
		t.Fatal(err)
	}
	if err := second.ReserveMemory(2<<20, 128); err == nil {
		t.Fatal("window growth exceeded the session budget")
	}
	if err := second.ReserveMemory(1<<20, 128); err != nil {
		t.Fatal(err)
	}
	first.Done()
	if err := second.ReserveMemory(yamuxSessionWindow-1<<20, 128); err != nil {
		t.Fatalf("closed stream kept its window growth: %v", err)
	}
	second.Done()
	if grown := budget.grown.Load(); grown != 0 {
		t.Fatalf("budget leaked %d bytes", grown)
	}
	// yamux may still try to grow a removed stream from a draining Read.
	if err := second.ReserveMemory(1<<20, 128); err == nil || budget.grown.Load() != 0 {
		t.Fatalf("removed stream grew its window: %v, budget %d", err, budget.grown.Load())
	}
}

func TestYamuxKeepaliveDetectsSilentPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent := &pipeDialer{server: make(chan net.Conn)}
		silent := make(chan net.Conn, 1)
		go func() {
			conn := <-parent.server
			silent <- conn
			_, _ = io.Copy(io.Discard, conn) // Never answers pings.
		}()
		mux := &Mux{Dialer: parent, Protocol: ProtocolYAMux}
		defer mux.Close()
		if err := mux.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer (<-silent).Close()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if state := mux.Snapshot(); !state.Accepting {
			t.Fatalf("session closed before its keepalive expired: %+v", state)
		}
		time.Sleep(15 * time.Second)
		synctest.Wait()
		state := mux.Snapshot()
		failure := netproxy.ClassifyFailure(state.Cause)
		if state.Accepting || !errors.Is(state.Cause, yamux.ErrKeepAliveTimeout) || failure.Reason != netproxy.ReasonDeadline || failure.Layer != netproxy.LayerYAMUX || failure.Scope != netproxy.ScopeSharedResource {
			t.Fatalf("silent peer was not detected: %+v (%+v)", state, failure)
		}
	})
}

// delayLink relays src to dst after a one-way delay with unlimited bandwidth
// and closes both ends once either fails.
func delayLink(dst, src net.Conn, delay time.Duration) {
	type chunk struct {
		data []byte
		at   time.Time
	}
	queue := make(chan chunk, 1024)
	stop, readDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			select {
			case queue <- chunk{bytes.Clone(buf[:n]), time.Now().Add(delay)}:
			case <-stop:
				return
			}
		}
	}()
	defer func() {
		close(stop)
		_ = src.Close()
		_ = dst.Close()
		<-readDone
	}()
	for {
		var c chunk
		select {
		case c = <-queue:
		case <-readDone:
			return
		}
		select {
		case <-time.After(time.Until(c.at)):
		case <-readDone:
			return
		}
		if _, err := dst.Write(c.data); err != nil {
			return
		}
	}
}

// delayedPipe is net.Pipe with a one-way delay in each direction.
func delayedPipe(delay time.Duration) (net.Conn, net.Conn) {
	client, clientEnd := net.Pipe()
	server, serverEnd := net.Pipe()
	go delayLink(serverEnd, clientEnd, delay)
	go delayLink(clientEnd, serverEnd, delay)
	return client, server
}

// A stream keeps its window growth until it closes. Idle long-lived streams,
// such as kept-alive HTTP/2 connections, must leave a session the budget to
// grow a new stream's window as far as the first stream's.
func TestYamuxIdleStreamsLeaveWindowForNewStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := delayedPipe(50 * time.Millisecond)
		config := yamux.DefaultConfig()
		config.LogOutput = io.Discard
		peer, err := yamux.Server(server, config, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		go func() {
			for {
				stream, err := peer.AcceptStream()
				if err != nil {
					return
				}
				go func() {
					chunk := make([]byte, 64<<10)
					for {
						if _, err := stream.Write(chunk); err != nil {
							return
						}
					}
				}()
			}
		}()
		session, err := newSession(ProtocolYAMux, &monitoredConn{Conn: client, failed: make(chan error, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		// Each stream downloads, then stays open and unread.
		download := func() time.Duration {
			stream, err := session.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if _, err := io.CopyN(io.Discard, stream, 16<<20); err != nil {
				t.Fatal(err)
			}
			return time.Since(start)
		}
		first := download()
		for range expandStreams - 2 {
			download()
		}
		if last := download(); last > first*5/4 {
			t.Fatalf("stream %d next to idle grown streams downloaded in %v, the first in %v", expandStreams, last, first)
		}
	})
}

// Grown streams keep the window budget of their session while idle. A
// session without budget for another full window must count as loaded and
// lose new streams to other sessions, or they stay at the initial window.
func TestYamuxPoolAvoidsSaturatedSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent := serveSingMux(t, ProtocolYAMux, func(_ muxRequest, stream net.Conn) {
			chunk := make([]byte, 64<<10)
			for {
				if _, err := stream.Write(chunk); err != nil {
					return
				}
			}
		})
		parent.wrapClient = func(_ int, conn net.Conn) net.Conn {
			client, link := net.Pipe()
			go delayLink(conn, link, 50*time.Millisecond)
			go delayLink(link, conn, 50*time.Millisecond)
			return client
		}
		// Room for a second TCP session besides the spare and the positions
		// kept for the datagram lanes.
		mux := &Mux{Dialer: parent, Protocol: ProtocolYAMux, MaxConnections: 5}
		t.Cleanup(func() { _ = mux.Close() })
		ctx := t.Context()
		if err := mux.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		open := func() net.Conn {
			conn, err := mux.DialContext(ctx, "tcp", "flood.example:80")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if _, err := conn.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
			return conn
		}
		download := func(conn net.Conn) time.Duration {
			start := time.Now()
			if _, err := io.CopyN(io.Discard, conn, 16<<20); err != nil {
				t.Fatal(err)
			}
			return time.Since(start)
		}
		loads := func() []int {
			h := poolHarness{dialer: mux}
			return h.loads()
		}
		grown := []net.Conn{open()}
		if err := mux.Connect(ctx); err != nil { // the new spare
			t.Fatal(err)
		}
		first := download(grown[0])
		for range expandStreams - 1 {
			conn := open()
			download(conn)
			grown = append(grown, conn)
		}
		if mux.Snapshot().RecoveryRequired {
			t.Fatalf("pool expanded below the stream threshold: loads=%v", loads())
		}
		// Closed streams keep their windows until they are reset, so the
		// session stays saturated with fewer user streams than the threshold.
		_ = grown[0].Close()
		_ = grown[1].Close()
		open()
		if got := loads(); got[0] != 2 || got[1] != 1 {
			t.Fatalf("new stream ignored a ready spare: loads=%v", got)
		}
		if !mux.Snapshot().RecoveryRequired {
			t.Fatalf("used spare was not replaced: loads=%v", loads())
		}
		if err := mux.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		// New streams avoid the saturated session although it carries fewer.
		for range expandStreams + 1 {
			open()
		}
		if got := loads(); len(got) != 3 || got[0] != 2 || got[1] != expandStreams+2 {
			t.Fatalf("streams were placed on the saturated session: loads=%v", got)
		}
		if last := download(open()); last > first*5/4 {
			t.Fatalf("new stream next to a saturated session downloaded in %v, the first in %v", last, first)
		}
	})
}

func TestYamuxResetsServerOpenedStreams(t *testing.T) {
	client, server := net.Pipe()
	session, err := newSession(ProtocolYAMux, &monitoredConn{Conn: client, failed: make(chan error, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	config := yamux.DefaultConfig()
	config.LogOutput = io.Discard
	peer, err := yamux.Server(server, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	stream, err := peer.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatalf("server-opened stream was not reset: %v", err)
	}
}

// exhaustedSession ran out of stream IDs: it stays open but fails every open.
type exhaustedSession struct{ session }

func (exhaustedSession) OpenStream(context.Context) (net.Conn, error) {
	return nil, yamux.ErrStreamsExhausted
}

func TestStreamIDExhaustionReplacesSession(t *testing.T) {
	mux := &Mux{Dialer: serveSingMux(t, ProtocolYAMux, func(muxRequest, net.Conn) {}), Protocol: ProtocolYAMux, MaxConnections: 1}
	t.Cleanup(func() { _ = mux.Close() })
	p := mux.pool()
	p.newLifecycle = func() *netproxy.SingleSession[*sessionResource] {
		return netproxy.NewSingleSession(netproxy.SingleSessionConfig[*sessionResource]{
			Layer: p.layer, RecoveryExecutor: netproxy.RecoveryDaemon,
			Establish: func(ctx context.Context) (*sessionResource, error) {
				resource, err := mux.establish(ctx)
				if err == nil {
					resource.session = exhaustedSession{resource.session}
				}
				return resource, err
			},
			IsConnected: (*sessionResource).connected,
			Observe:     mux.observe,
			Close:       func(resource *sessionResource) error { return resource.session.Close() },
		})
	}
	if err := mux.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
	if failure := netproxy.ClassifyFailure(err); !errors.Is(err, yamux.ErrStreamsExhausted) || failure.Scope != netproxy.ScopeSharedResource {
		t.Fatalf("open on an exhausted session = %v (%+v)", err, failure)
	}
	if state := mux.Snapshot(); state.Accepting || !state.RecoveryRequired || state.EpisodeID != 1 {
		t.Fatalf("exhausted session was kept: %+v", state)
	}
}
