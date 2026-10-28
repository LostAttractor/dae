// SPDX-License-Identifier: AGPL-3.0-only

package smuxtest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

type recordingConn struct {
	net.Conn
	writes [][]byte
	short  bool
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	if c.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}

func TestWriteFrameKeepsHeaderAndPayloadTogether(t *testing.T) {
	conn := new(recordingConn)
	s := &Session{conn: conn}
	payload := []byte("datagram")
	if err := s.WriteFrame(Version, CmdPSH, 3, payload); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("one frame used %d carrier writes", len(conn.writes))
	}
	frame := conn.writes[0]
	if len(frame) != headerSize+len(payload) || frame[0] != Version || frame[1] != CmdPSH || binary.LittleEndian.Uint16(frame[2:]) != uint16(len(payload)) || binary.LittleEndian.Uint32(frame[4:]) != 3 || !bytes.Equal(frame[headerSize:], payload) {
		t.Fatalf("wrong frame: %x", frame)
	}
	if err := s.WriteFrame(Version, CmdFIN, 3, nil); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 2 || len(conn.writes[1]) != headerSize || binary.LittleEndian.Uint16(conn.writes[1][2:]) != 0 {
		t.Fatal("control frame retained the previous payload")
	}
}

func TestWriteFrameRejectsShortCarrierWrite(t *testing.T) {
	s := &Session{conn: &recordingConn{short: true}}
	if err := s.WriteFrame(Version, CmdPSH, 1, []byte("packet")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}
