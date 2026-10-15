package juicity

import (
	"fmt"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

type Conn struct {
	*quic.Stream
	Metadata     *Metadata
	lAddr, rAddr net.Addr

	writeMutex sync.Mutex
	onceWrite  bool

	closeOnce sync.Once
	closeErr  error
	lease     *netproxy.Lease
	fail      func(error)
}

func (c *Conn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *Conn) wrap(err error, op netproxy.Operation) error {
	if c.lease == nil {
		return err
	}
	return common.WrapQUICError(err, c.lease.Resource(), c.lease, op, c.fail)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	defer func() { err = c.wrap(err, netproxy.OpWrite) }()
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.onceWrite {
		return c.Stream.Write(b)
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	switch c.Metadata.Network {
	case "tcp":
		buf.WriteByte(1)
	case "udp":
		buf.WriteByte(3)
	default:
		return 0, fmt.Errorf("invalid Juicity network: %s", c.Metadata.Network)
	}
	if err := c.Metadata.appendTo(buf); err != nil {
		return 0, err
	}

	headerLen := buf.Len()
	buf.Write(b)
	written, err := c.Stream.Write(buf.Bytes())
	if err != nil {
		return max(0, written-headerLen), fmt.Errorf("write request: %w", err)
	}
	c.onceWrite = true
	return len(b), nil
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Stream.Read(b)
	return n, c.wrap(err, netproxy.OpRead)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		if c.lease != nil {
			c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerQUIC, Phase: netproxy.OpClose, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
		}
		c.closeErr = c.close()
	})
	return c.closeErr
}

func (c *Conn) CloseWrite() error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// As documented by the quic-go library, this doesn't actually close the entire stream.
	// It prevents further writes, which in turn will result in an EOF signal being sent the other side of stream when
	// reading.
	// We can still read from this stream.
	return c.wrap(c.Stream.Close(), netproxy.OpCloseWrite)
}

func (c *Conn) close() error {
	c.Stream.CancelRead(0)
	c.Stream.CancelWrite(0)
	return nil
}

var _ net.Conn = &Conn{}

func newConn(stream *quic.Stream, mdata *Metadata) *Conn {
	return &Conn{
		Stream:   stream,
		Metadata: mdata,
	}
}

func (c *Conn) LocalAddr() net.Addr  { return c.lAddr }
func (c *Conn) RemoteAddr() net.Addr { return c.rAddr }
