package protocol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

var testHeader = []byte("header")

type firstWriteConn struct {
	net.Conn
	first FirstWrite
}

func (c *firstWriteConn) Read(p []byte) (int, error) {
	if err := c.first.Flush(c.flush); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *firstWriteConn) Write(p []byte) (int, error) {
	c.first.Lock()
	defer c.first.Unlock()
	return c.first.Write(c.Conn, testHeader, p)
}

func (c *firstWriteConn) flush() error {
	_, err := c.first.Write(c.Conn, testHeader, nil)
	return err
}

// A peer may reply after part of the first write and read on only once the
// client has read the reply.
func TestFirstWriteReadDoesNotWaitForBlockedWrite(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &firstWriteConn{Conn: local}
	payload := bytes.Repeat([]byte{'x'}, 64<<10)
	written := make(chan error, 1)
	go func() {
		n, err := conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		written <- err
	}()
	got := make([]byte, 1<<10)
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.HasPrefix(got, testHeader) {
		t.Fatalf("peer read %q, %v", got[:len(testHeader)], err)
	}
	read := make(chan error, 1)
	go func() {
		reply := make([]byte, 5)
		_, err := io.ReadFull(conn, reply)
		if err == nil && string(reply) != "reply" {
			err = errors.New("wrong reply " + string(reply))
		}
		read <- err
	}()
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Write([]byte("reply")); err != nil {
		t.Fatalf("Read waited for the first Write: %v", err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, len(testHeader)+len(payload)-len(got))
	if _, err := io.ReadFull(peer, rest); err != nil || !bytes.Equal(append(got, rest...)[len(testHeader):], payload) {
		t.Fatalf("payload after the header lost: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

type shortConn struct {
	net.Conn
	written bytes.Buffer
	writes  int
}

func (c *shortConn) Write(p []byte) (int, error) {
	c.writes++
	return c.written.Write(p[:len(p)-2])
}

func TestFirstWriteFailureIsPermanent(t *testing.T) {
	carrier := &shortConn{}
	conn := &firstWriteConn{Conn: carrier}
	if n, err := conn.Write([]byte("abc")); n != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write = %d, %v; want the payload bytes written", n, err)
	}
	if _, err := conn.Write([]byte("abc")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("second Write = %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Read = %v", err)
	}
	conn.first.Lock()
	err := conn.first.FlushLocked(conn.flush)
	conn.first.Unlock()
	if !errors.Is(err, io.ErrShortWrite) || carrier.writes != 1 {
		t.Fatalf("FlushLocked = %v after %d carrier writes", err, carrier.writes)
	}
}
