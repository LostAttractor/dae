package mux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestWriteSegmentsLargePayload(t *testing.T) {
	for _, size := range []int{0, 65535, 65536, 2*65535 + 3} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			carrier := new(frameConn)
			conn := NewConn(carrier, MuxOption{ID: [2]byte{1, 2}, Host: "127.0.0.1"})
			payload := bytes.Repeat([]byte{'x'}, size)
			if n, err := conn.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("Write = %d, %v", n, err)
			}
			wire := carrier.writes.Bytes()
			wire = wire[2+int(binary.BigEndian.Uint16(wire)):]
			reader := NewConn(&frameConn{reader: bytes.NewReader(wire)}, MuxOption{})
			got, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("decoded %d/%d bytes: %v", len(got), len(payload), err)
			}
		})
	}
}

func TestLargeWriteCountsCompletedFrames(t *testing.T) {
	carrier := &frameConn{shortAt: 3}
	conn := NewConn(carrier, MuxOption{Host: "127.0.0.1"})
	payload := make([]byte, 2*65535+3)
	if n, err := conn.Write(payload); n != 2*65535-1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial large Write = %d, %v", n, err)
	}
	if n, err := conn.Write([]byte("retry")); n != 0 || !errors.Is(err, io.ErrShortWrite) || carrier.calls != 3 {
		t.Fatalf("retry after partial frame = %d, %v; %d carrier writes", n, err, carrier.calls)
	}
}
