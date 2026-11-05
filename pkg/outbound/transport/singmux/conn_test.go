package singmux

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

func testLeasedStream(t *testing.T) (*Mux, *leasedStream, *smuxtest.Session) {
	t.Helper()
	parent := &pipeDialer{server: make(chan net.Conn)}
	accepted := acceptSmuxSessions(parent, 1)
	dialer := &Mux{Dialer: parent, MaxConnections: 1}
	t.Cleanup(func() { _ = dialer.Close() })
	if err := dialer.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	server := waitForSmuxSessions(t, accepted, 1)[0]
	t.Cleanup(func() { _ = server.Close() })
	conn, err := dialer.pool().OpenStream(t.Context(), laneStream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return dialer, conn.(*leasedStream), server
}

func TestStreamCloseReportsLocalCleanup(t *testing.T) {
	dialer, stream, _ := testLeasedStream(t)
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := stream.Write([]byte("after close"))
	failure := netproxy.ClassifyFailure(err)
	if !errors.Is(err, io.ErrClosedPipe) || failure.Origin != netproxy.OriginLocalCleanup || failure.Scope != netproxy.ScopeStream || failure.Phase != netproxy.OpWrite || failure.Resource != stream.handle.Ref() {
		t.Fatalf("write after Close: %+v", failure)
	}
	if state := dialer.Snapshot(); !state.Accepting || state.EpisodeID != 0 || state.RecoveryRequired {
		t.Fatalf("stream cleanup disturbed the shared session: %+v", state)
	}
}

func TestStreamClosePreservesCarrierFailure(t *testing.T) {
	for _, order := range []string{"carrier first", "local close first"} {
		t.Run(order, func(t *testing.T) {
			_, stream, server := testLeasedStream(t)
			if order == "local close first" {
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-stream.handle.Lease().Done():
			case <-time.After(time.Second):
				t.Fatal("carrier failure was not observed")
			}
			_ = stream.Close()
			_, err := stream.Read(make([]byte, 1))
			failure := netproxy.ClassifyFailure(err)
			if err == nil || failure.Scope != netproxy.ScopeSharedResource || failure.Origin == netproxy.OriginLocalCleanup || !errors.Is(err, stream.handle.Resource().monitor.cause()) {
				t.Fatalf("Close hid the carrier failure: %+v", failure)
			}
		})
	}
}

func TestStreamReadDeadlineRemainsFailure(t *testing.T) {
	_, stream, _ := testLeasedStream(t)
	if err := stream.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := stream.Read(make([]byte, 1))
	failure := netproxy.ClassifyFailure(err)
	if failure.Reason != netproxy.ReasonDeadline || failure.Origin == netproxy.OriginLocalCleanup {
		t.Fatalf("upstream read deadline was suppressed: %+v", failure)
	}
}

// A server-first protocol never writes, so Read sends the stream request.
func TestStreamReadSendsPendingRequest(t *testing.T) {
	_, stream, server := testLeasedStream(t)
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	conn := &Conn{Conn: stream, addr: "192.0.2.1:25"}
	read := make(chan string, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		read <- string(buf[:n])
	}()
	var want bytes.Buffer
	if err := WriteStreamRequest(&want, &StreamRequest{Destination: "192.0.2.1:25"}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, want.Len())
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("stream request = %x, %v; want %x", got, err, want.Bytes())
	}
	if _, err := peer.Write([]byte("\x00220 ready")); err != nil {
		t.Fatal(err)
	}
	if got := <-read; got != "220 ready" {
		t.Fatalf("Read = %q", got)
	}
}
