package socks

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadAddrInto(t *testing.T) {
	buf := make([]byte, MaxAddrLen)
	for _, wire := range [][]byte{
		append([]byte{ATypDomain, 255}, append(bytes.Repeat([]byte{'x'}, 255), 0, 53)...),
		{ATypIP4, 192, 0, 2, 1, 1, 187},
		{ATypIP6, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53},
	} {
		stream := bytes.NewReader(append(bytes.Clone(wire), []byte("payload")...))
		addr, err := ReadAddrInto(iotest.OneByteReader(stream), buf)
		if err != nil || !bytes.Equal(addr, wire) {
			t.Fatalf("decoded address = %x, %v; want %x", addr, err, wire)
		}
		if &addr[0] != &buf[0] {
			t.Fatal("decoder did not use the supplied buffer")
		}
		if stream.Len() != len("payload") {
			t.Fatal("decoder consumed payload bytes")
		}
	}
}

func TestReadAddrIntoShortBufferDoesNotConsumeInput(t *testing.T) {
	stream := bytes.NewReader([]byte{ATypIP4, 192, 0, 2, 1, 1, 187})
	for _, size := range []int{0, 1, MaxAddrLen - 1} {
		addr, err := ReadAddrInto(stream, make([]byte, size))
		if addr != nil || !errors.Is(err, io.ErrShortBuffer) || stream.Len() != 7 {
			t.Fatalf("buffer size %d: address=%x error=%v remaining=%d", size, addr, err, stream.Len())
		}
	}
}
