package anytls

import (
	"errors"
	"os"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

// AnyTLS has no per-stream receive window. Bound each unread backlog so a
// stalled consumer cannot block siblings or retain unlimited memory.
const maxStreamReceiveBuffer = 1 << 20

func (c *stream) receive(p []byte) {
	c.receiveMu.Lock()
	if c.receiveErr != nil {
		c.receiveMu.Unlock()
		return
	}
	if c.received == nil {
		c.received = pool.GetBytesBuffer()
	}
	if c.received.Len()+len(p) > maxStreamReceiveBuffer {
		c.receiveMu.Unlock()
		c.sendFIN.Store(true)
		c.failStream(netproxy.WrapFailure(errors.New("AnyTLS stream receive buffer exhausted"), netproxy.Failure{
			Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream,
			Layer: netproxy.LayerAnyTLS, Origin: netproxy.OriginLocalProtocol, Reason: netproxy.ReasonCapacity, Phase: netproxy.OpRead,
		}))
		return
	}
	_, _ = c.received.Write(p)
	c.wakeReader()
	c.receiveMu.Unlock()
}

// readMutex serializes callers, including partial packet framing in ReadFrom.
func (c *stream) read(p []byte) (int, error) {
	for {
		select {
		case <-c.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		c.receiveMu.Lock()
		if c.received != nil {
			n, _ := c.received.Read(p)
			if c.received.Len() == 0 {
				pool.PutBytesBuffer(c.received)
				c.received = nil
			}
			c.receiveMu.Unlock()
			return n, nil
		}
		err := c.receiveErr
		c.receiveMu.Unlock()
		if err != nil || len(p) == 0 {
			return 0, err
		}
		select {
		case <-c.receiveReady:
		case <-c.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *stream) wakeReader() {
	select {
	case c.receiveReady <- struct{}{}:
	default:
	}
}

func (c *stream) stopReads(err error, discard bool) {
	c.receiveMu.Lock()
	if c.receiveErr == nil || discard {
		c.receiveErr = err
	}
	if discard && c.received != nil {
		pool.PutBytesBuffer(c.received)
		c.received = nil
	}
	c.wakeReader()
	c.receiveMu.Unlock()
}
