package juicity

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

type Conn struct {
	*quic.Stream
	Metadata     *Metadata
	lAddr, rAddr net.Addr

	first protocol.FirstWrite

	closeOnce sync.Once
	wroteFIN  atomic.Bool
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

// Write sends the request (network and target) in the same stream write as
// the first payload.
func (c *Conn) Write(b []byte) (n int, err error) {
	defer func() { err = c.wrap(err, netproxy.OpWrite) }()
	c.first.Lock()
	defer c.first.Unlock()
	return c.writeLocked(b)
}

// writeLocked writes any pending request followed by b. The caller holds first.
func (c *Conn) writeLocked(b []byte) (int, error) {
	if !c.first.Pending() {
		return c.first.Write(c.Stream, nil, b)
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	switch c.Metadata.Network {
	case "tcp":
		buf.WriteByte(1)
	case "udp":
		buf.WriteByte(3)
	default:
		return 0, c.first.Done(fmt.Errorf("invalid Juicity network: %s", c.Metadata.Network))
	}
	if err := c.Metadata.appendTo(buf); err != nil {
		return 0, c.first.Done(err)
	}
	return c.first.Write(c.Stream, buf.Bytes(), b)
}

// flush sends a pending request alone, for a peer that speaks first.
func (c *Conn) flush() error {
	_, err := c.writeLocked(nil)
	return err
}

// Read sends a pending TCP request first so server-first protocols work. UDP
// streams leave it to the first datagram: replies follow one, and their
// readers start before the first write.
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) > 0 && c.Metadata.Network == "tcp" {
		if err := c.first.Flush(c.flush); err != nil {
			return 0, c.wrap(err, netproxy.OpWrite)
		}
	}
	n, err := c.Stream.Read(b)
	return n, c.wrap(err, netproxy.OpRead)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		if c.lease != nil {
			c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerQUIC, Phase: netproxy.OpClose, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
		}
		common.CloseStream(c.Stream, c.wroteFIN.Load())
	})
	return nil
}

func (c *Conn) CloseWrite() error {
	c.first.Lock()
	defer c.first.Unlock()
	if err := c.first.FlushLocked(c.flush); err != nil {
		return c.wrap(err, netproxy.OpWrite)
	}

	// As documented by the quic-go library, this doesn't actually close the entire stream.
	// It prevents further writes, which in turn will result in an EOF signal being sent the other side of stream when
	// reading.
	// We can still read from this stream.
	err := c.Stream.Close()
	if err == nil {
		c.wroteFIN.Store(true)
	}
	return c.wrap(err, netproxy.OpCloseWrite)
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
