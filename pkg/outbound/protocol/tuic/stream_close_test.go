package tuic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/quic-go"
)

// closeFixture is one tuic connection to a loopback QUIC peer configured by
// peer, owned by a Runtime as an outbound chain is. Like a tuic server, the
// peer reads every unidirectional stream.
type closeFixture struct {
	runtime *netproxy.Runtime
	dialer  *Dialer
	server  *quic.Conn
}

func newCloseFixture(t *testing.T, ctx context.Context, peer quic.Config) *closeFixture {
	t.Helper()
	peer.EnableDatagrams = true
	listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), &peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *quic.Conn, 1)
	go func() {
		if c, err := listener.Accept(ctx); err == nil {
			accepted <- c
		}
	}()
	d, err := NewDialer(loopbackPacketParent{}, protocol.Header{ProxyAddress: listener.Addr().String(), User: "00000000-0000-0000-0000-000000000000", Password: "test", Feature1: "bbr", TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"tuic-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := netproxy.NewRuntime(netproxy.Layer{Data: d, Sessions: []netproxy.Session{d}, Resources: []io.Closer{d}})
	t.Cleanup(func() {
		runtime.Retire()
		wait, cancel := context.WithTimeout(context.Background(), 2*netproxy.CloseLinger)
		defer cancel()
		if err := runtime.Wait(wait); errors.Is(err, context.DeadlineExceeded) {
			t.Error("runtime did not close")
		}
	})
	if err := runtime.Session().Connect(ctx); err != nil {
		t.Fatal(err)
	}
	f := &closeFixture{runtime: runtime, dialer: d}
	select {
	case f.server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = f.server.CloseWithError(0, "") })
	go func() {
		for {
			stream, err := f.server.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, stream) }()
		}
	}()
	return f
}

// open dials a stream, sends its CONNECT alone and accepts it on the peer,
// past the CONNECT header.
func (f *closeFixture) open(t *testing.T, ctx context.Context) (net.Conn, *quic.Stream, *bufio.Reader) {
	t.Helper()
	client, err := f.runtime.Dialer().DialContext(ctx, "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// The peer sees the stream only once the deferred CONNECT is sent.
	if _, err := client.Write(nil); err != nil {
		t.Fatal(err)
	}
	remote, err := f.server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	request := bufio.NewReader(remote)
	if _, err := readConnectFixture(request); err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client, remote, request
}

// The relay's order when the target closes first: the client reads EOF, then
// sends its last upload, CloseWrite and Close. The peer must read all of it,
// whether it reads at once or only after the stream is closed, also when the
// path was retired and closing the stream closes the connection.
func TestCloseAfterCloseWriteKeepsUpload(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, 256<<10)
	for _, retire := range []bool{false, true} {
		for _, delay := range []time.Duration{0, 300 * time.Millisecond} {
			t.Run(fmt.Sprintf("retired %v, reader after %v", retire, delay), func(t *testing.T) {
				for i := range 20 {
					t.Run(fmt.Sprint(i), func(t *testing.T) {
						t.Parallel()
						ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
						defer cancel()
						f := newCloseFixture(t, ctx, quic.Config{})
						client, remote, request := f.open(t, ctx)
						if retire {
							f.runtime.Retire()
						}
						if err := remote.Close(); err != nil {
							t.Fatal(err)
						}
						got := make(chan error, 1)
						go func() {
							time.Sleep(delay)
							data, err := io.ReadAll(request)
							if err == nil && len(data) != len(payload) {
								err = fmt.Errorf("peer read %d of %d bytes", len(data), len(payload))
							}
							got <- err
						}()
						if _, err := io.ReadAll(client); err != nil {
							t.Fatal(err)
						}
						if _, err := client.Write(payload); err != nil {
							t.Fatal(err)
						}
						if err := netproxy.CloseWrite(client); err != nil {
							t.Fatal(err)
						}
						_ = client.Close()
						if err := <-got; err != nil {
							t.Fatal(err)
						}
					})
				}
			})
		}
	}
}

// Close without CloseWrite abandons the upload: it wakes a Write blocked on
// flow control, and the peer sees the stream reset.
func TestCloseWithoutCloseWriteResets(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	f := newCloseFixture(t, ctx, quic.Config{})
	client, _, request := f.open(t, ctx)
	written := make(chan error, 1)
	go func() {
		// Far beyond the peer's stream window; the peer is not reading.
		_, err := client.Write(make([]byte, 4<<20))
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("write did not wait for flow control: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = client.Close()
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked write succeeded after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake the blocked Write")
	}
	_, err := io.ReadAll(request)
	if reset, ok := errors.AsType[*quic.StreamError](err); !ok || !reset.Remote {
		t.Fatalf("peer read error = %v, want a reset", err)
	}
}

// A retired path whose peer never reads its last stream closes the
// connection after netproxy.CloseLinger.
func TestRetiredCloseWaitIsBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*netproxy.CloseLinger)
	defer cancel()
	f := newCloseFixture(t, ctx, quic.Config{})
	client, _, _ := f.open(t, ctx)
	if _, err := client.Write([]byte("unread")); err != nil {
		t.Fatal(err)
	}
	if err := netproxy.CloseWrite(client); err != nil {
		t.Fatal(err)
	}
	f.runtime.Retire()
	start := time.Now()
	_ = client.Close()
	if err := f.runtime.Wait(ctx); errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("runtime did not close")
	}
	if waited := time.Since(start); waited < netproxy.CloseLinger || waited > netproxy.CloseLinger+time.Second {
		t.Fatalf("closing took %v, want about %v", waited, netproxy.CloseLinger)
	}
}

// A peer granting about QUIC's cap of 2^60 streams, as sing-box's tuic
// server does, cannot raise its limit once a stream ended, so its credit
// never returns to the highest grant; a retired path still closes at once.
func TestRetiredCloseSkipsUnlimitedCredit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*netproxy.CloseLinger)
	defer cancel()
	f := newCloseFixture(t, ctx, quic.Config{MaxIncomingStreams: 1 << 60, MaxIncomingUniStreams: 1 << 60})
	client, remote, request := f.open(t, ctx)
	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(client); err != nil {
		t.Fatal(err)
	}
	if err := netproxy.CloseWrite(client); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(request); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	f.runtime.Retire()
	start := time.Now()
	if err := f.runtime.Wait(ctx); errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("runtime did not close")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("closing took %v", waited)
	}
}

// A failed member closes its connection at once, even with a stream the peer
// has not finished, and the retired ring then waits for nothing.
func TestFailedMemberClosesAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	f := newCloseFixture(t, ctx, quic.Config{})
	client, _, _ := f.open(t, ctx)
	var member *clientImpl
	if err := f.dialer.clientRing.Allocate(ctx, false, func(_ context.Context, c *clientImpl) error {
		member = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	member.failConnection(errors.New("member failed"))
	select {
	case <-f.server.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("failed member kept its connection open")
	}
	f.runtime.Retire()
	start := time.Now()
	_ = client.Close()
	if err := f.runtime.Wait(ctx); errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("runtime did not close")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("closing a failed ring took %v", waited)
	}
}
