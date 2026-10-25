package singmux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type Conn struct {
	net.Conn

	layer      netproxy.FailureLayer
	addr       string
	udp        bool
	packetAddr bool

	onceRead  bool
	onceWrite bool
}

const maxRejectionMessageBytes = 1024

func readResponse(conn net.Conn, layer netproxy.FailureLayer) (err error) {
	var status uint8
	err = binary.Read(conn, binary.BigEndian, &status)
	if err != nil {
		return
	}
	if status == statusError {
		var message []byte
		message, err = io.ReadAll(io.LimitReader(conn, maxRejectionMessageBytes+1))
		if err != nil {
			return
		}
		return rejection(layer, message)
	}
	return
}

// rejection is the failure of a stream whose response carried message, read
// up to maxRejectionMessageBytes+1 bytes.
func rejection(layer netproxy.FailureLayer, message []byte) error {
	suffix := ""
	if len(message) > maxRejectionMessageBytes {
		message = message[:maxRejectionMessageBytes]
		suffix = " (truncated)"
	}
	return netproxy.WrapFailure(fmt.Errorf("%s target rejected connection: %s%s", layer, message, suffix), netproxy.Failure{Scope: netproxy.ScopeStream, Layer: layer, Origin: netproxy.OriginTarget, Reason: netproxy.ReasonRejected, Phase: netproxy.OpDial})
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if !c.onceRead {
		err = readResponse(c.Conn, c.layer)
		if err != nil {
			return
		}
		c.onceRead = true
	}
	return c.Conn.Read(b)
}

type StreamRequest struct {
	Destination string
	UDP         bool
	PacketAddr  bool
}

func WriteStreamRequest(buf *bytes.Buffer, streamRequest *StreamRequest) error {
	var flags uint16
	if streamRequest.UDP {
		flags |= flagUDP
	}
	if streamRequest.PacketAddr {
		flags |= flagAddr
	}
	binary.Write(buf, binary.BigEndian, flags)
	return socks5.WriteAddr(streamRequest.Destination, buf)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.onceWrite {
		return c.Conn.Write(b)
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	err = WriteStreamRequest(buf, &StreamRequest{
		Destination: c.addr,
		UDP:         c.udp,
		PacketAddr:  c.packetAddr,
	})
	if err != nil {
		return
	}
	c.onceWrite = true
	buf.Write(b)
	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

// CloseWrite half-closes the stream, first sending the stream request if no
// Write has. A stream that cannot half-close reports so before sending it.
func (c *Conn) CloseWrite() error {
	if !halfCloses(c.Conn) {
		return errors.ErrUnsupported
	}
	if !c.onceWrite {
		if _, err := c.Write(nil); err != nil {
			return err
		}
	}
	return netproxy.CloseWrite(c.Conn)
}

// halfCloses reports whether conn, or the session stream it leases, can end
// only its write side. A smux v1 FIN ends both directions.
func halfCloses(conn net.Conn) bool {
	if leased, ok := conn.(*leasedStream); ok {
		conn = leased.Conn
	}
	_, ok := conn.(netproxy.CloseWriter)
	return ok
}

func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

type leasedStream struct {
	net.Conn
	layer  netproxy.FailureLayer
	handle *netproxy.SingleSessionHandle[*sessionResource]
	lease  *netproxy.Lease
	// release returns the stream's pool reservation once.
	release func()
}

func (c *leasedStream) DependencyLease() *netproxy.Lease { return c.lease }
func (c *leasedStream) failure(err error, phase netproxy.Operation) error {
	if err == nil {
		return nil
	}
	fact := netproxy.ClassifyFailure(err)
	cause := c.handle.Resource().cause()
	if cause != nil {
		err = cause
		fact = netproxy.ClassifyFailure(cause)
		fact.Scope = netproxy.ScopeSharedResource
	} else if err == io.EOF && phase == netproxy.OpRead {
		return io.EOF
	} else if netproxy.ClassifyFailure(c.lease.Cause()).Origin == netproxy.OriginLocalCleanup {
		// Close records cleanup before unblocking I/O, so whatever the stream
		// returns then, a yamux read deadline included, is that closure. A
		// carrier failure above still takes precedence.
		fact = netproxy.Failure{Scope: netproxy.ScopeStream, Origin: netproxy.OriginLocalCleanup}
	} else if fact.Scope == netproxy.ScopeUnknown {
		fact.Scope = netproxy.ScopeStream
	}
	fact.Resource, fact.Stream, fact.Phase = c.handle.Ref(), c.lease.Stream(), phase
	if fact.Layer == netproxy.LayerUnknown {
		fact.Layer = c.layer
	}
	wrapped := netproxy.WrapFailure(err, fact)
	if fact.Scope == netproxy.ScopeSharedResource {
		c.handle.Abort(wrapped)
	} else if fact.Scope == netproxy.ScopeStream {
		c.lease.Invalidate(wrapped)
	}
	return wrapped
}
func (c *leasedStream) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	return n, c.failure(err, netproxy.OpRead)
}
func (c *leasedStream) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	return n, c.failure(err, netproxy.OpWrite)
}
func (c *leasedStream) CloseWrite() error {
	err := netproxy.CloseWrite(c.Conn)
	if err == errors.ErrUnsupported {
		// Unwrapped: callers compare it exactly.
		return err
	}
	return c.failure(err, netproxy.OpCloseWrite)
}
func (c *leasedStream) Close() error {
	defer c.release()
	c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.handle.Ref(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: c.layer, Origin: netproxy.OriginLocalCleanup}))
	return c.Conn.Close()
}
