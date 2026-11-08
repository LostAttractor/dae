package netproxy

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestDatagramWriterCachesTheRawSocket(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := server.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, received := []byte("packet"), make([]byte, 16)
	for _, tracked := range []bool{false, true} {
		var conn net.Conn = client
		if tracked {
			conn = TrackConn(conn, func() {})
		}
		writer := NewDatagramWriter(conn)
		if writer.socket == nil {
			t.Fatal("connected UDP socket was not cached")
		}
		measure := func(write func([]byte) (int, error)) float64 {
			return testing.AllocsPerRun(1000, func() {
				if n, err := write(packet); n != len(packet) || err != nil {
					t.Fatalf("send = %d, %v", n, err)
				}
				if n, err := server.Read(received); n != len(packet) || err != nil || string(received[:n]) != string(packet) {
					t.Fatalf("received = %d, %v", n, err)
				}
			})
		}
		uncached := measure(func(b []byte) (int, error) { return TryWrite(conn, b) })
		cached := measure(writer.TryWrite)
		t.Logf("tracked=%v: allocations per datagram %.2f -> %.2f", tracked, uncached, cached)
		if uncached-cached < 0.5 {
			t.Fatalf("did not remove the per-packet rawConn allocation: %.2f -> %.2f", uncached, cached)
		}
	}
}

// A protocol wrapper remains in the write path, even if it embeds a native
// socket. Caching must only look through known ownership wrappers.
func TestDatagramWriterKeepsProtocolWrappers(t *testing.T) {
	conn := &datagramWriteCounter{}
	writer := NewDatagramWriter(TrackConn(conn, func() {}))
	if n, err := writer.TryWrite([]byte("packet")); n != 0 || !errors.Is(err, errors.ErrUnsupported) || conn.writes != 0 {
		t.Fatalf("unsupported send = %d, %v, writes=%d", n, err, conn.writes)
	}
	if n, err := writer.Write([]byte("packet")); n != 6 || err != nil || conn.writes != 1 {
		t.Fatalf("fallback send = %d, %v, writes=%d", n, err, conn.writes)
	}
}

type datagramWriteCounter struct {
	net.Conn
	writes int
}

func (c *datagramWriteCounter) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}
