package smux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

func TestUDPReadPreservesDatagramBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payload  []byte
		fragment bool
		capacity int
	}{
		{"coalesced", []byte("first"), false, 128},
		{"fragmented", []byte("first"), true, 128},
		{"large", bytes.Repeat([]byte{'x'}, 40000), false, 65535},
		{"short buffer", []byte("first"), false, 2},
		{"empty datagram", nil, false, 128},
		{"empty buffer", []byte("first"), false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stream, server := testLeasedStream(t)
			peer, err := server.AcceptStream()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
			var wire bytes.Buffer
			wire.WriteByte(0) // Successful stream response.
			for _, payload := range [][]byte{tc.payload, []byte("next")} {
				if err := socks5.WriteAddr("192.0.2.1:53", &wire); err != nil {
					t.Fatal(err)
				}
				wire.Write(binary.BigEndian.AppendUint16(nil, uint16(len(payload))))
				wire.Write(payload)
			}
			done := make(chan error, 1)
			go func() {
				data := wire.Bytes()
				for len(data) > 0 {
					size := len(data)
					if tc.fragment {
						size = 1
					}
					if _, err := peer.Write(data[:size]); err != nil {
						done <- err
						return
					}
					data = data[size:]
				}
				done <- nil
			}()
			conn := &UDPConn{Conn: Conn{Conn: stream}}
			buf := make([]byte, tc.capacity)
			n, from, err := conn.ReadFrom(buf)
			var wantErr error
			if len(tc.payload) > len(buf) {
				wantErr = io.ErrShortBuffer
			}
			if !errors.Is(err, wantErr) || from == nil || from.String() != "192.0.2.1:53" || !bytes.Equal(buf[:n], tc.payload[:min(len(tc.payload), len(buf))]) {
				t.Fatalf("first datagram: n=%d from=%v err=%v", n, from, err)
			}
			buf = make([]byte, 128)
			n, from, err = conn.ReadFrom(buf)
			if err != nil || from == nil || from.String() != "192.0.2.1:53" || string(buf[:n]) != "next" {
				t.Fatalf("next datagram: n=%d from=%v err=%v payload=%q", n, from, err, buf[:n])
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
