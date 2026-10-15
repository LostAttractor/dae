package mux

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type closeTrackingConn struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
	writes      int
}

func (c *closeTrackingConn) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *closeTrackingConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

func (c *closeTrackingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *closeTrackingConn) LocalAddr() net.Addr              { return nil }
func (c *closeTrackingConn) RemoteAddr() net.Addr             { return nil }
func (c *closeTrackingConn) SetDeadline(time.Time) error      { return nil }
func (c *closeTrackingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeTrackingConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnCloseUnblocksReadWithoutWriting(t *testing.T) {
	underlay := &closeTrackingConn{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	conn := NewConn(underlay, MuxOption{})
	readDone := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readDone <- err
	}()
	<-underlay.readStarted

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
	if underlay.writes != 0 {
		t.Fatalf("underlay writes = %d, want 0", underlay.writes)
	}
}
