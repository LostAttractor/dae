package vless

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

// Conn sends the request header with the first write and removes the one
// response header without buffering payload bytes. Exact reads let Vision
// safely hand its TLS carrier over to direct mode.
type Conn struct {
	net.Conn
	readMu  sync.Mutex
	first   protocol.FirstWrite
	request []byte // guarded by first; nil once sent
	// readFlush makes a Read before any write send the request alone, so
	// server-first protocols work. Packet streams leave it unset: replies
	// follow a datagram, and their readers start before the first write.
	// Vision leaves it unset to send the request with its first record.
	readFlush         bool
	response          [257]byte
	responseUsed      int
	ready             bool
	readErr, writeErr error
}

func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *Conn) TLSConn() net.Conn {
	if provider, ok := c.Conn.(interface{ TLSConn() net.Conn }); ok {
		return provider.TLSConn()
	}
	return c.Conn
}
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) > 0 && c.readFlush {
		if err := c.first.Flush(c.flush); err != nil {
			return 0, err
		}
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	if !c.ready {
		if c.responseUsed < 2 {
			n, err := io.ReadFull(c.Conn, c.response[c.responseUsed:2])
			c.responseUsed += n
			if err != nil {
				return 0, err
			}
		}
		if c.response[0] != 0 {
			c.readErr = netproxy.WrapFailure(fmt.Errorf("unsupported VLESS response version: %d", c.response[0]), netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Reason: netproxy.ReasonProtocol, Origin: netproxy.OriginPeer, Phase: netproxy.OpRead})
			return 0, c.readErr
		}
		size := 2 + int(c.response[1])
		n, err := io.ReadFull(c.Conn, c.response[c.responseUsed:size])
		c.responseUsed += n
		if err != nil {
			return 0, err
		}
		c.ready = true
	}
	return c.Conn.Read(p)
}
func (c *Conn) Write(p []byte) (int, error) {
	c.first.Lock()
	defer c.first.Unlock()
	return c.write(p)
}

// write sends any pending request and p in one carrier write and reports the
// bytes of p written. The caller holds first.
func (c *Conn) write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	n, err := c.first.Write(c.Conn, c.request, p)
	c.request = nil
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeErr = err
	}
	return n, err
}

// flush sends a pending request alone. The caller holds first.
func (c *Conn) flush() error {
	_, err := c.write(nil)
	return err
}
func (c *Conn) CloseWrite() error {
	c.first.Lock()
	defer c.first.Unlock()
	if err := c.first.FlushLocked(c.flush); err != nil {
		return err
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	c.writeErr = net.ErrClosed
	if writer, ok := c.Conn.(netproxy.CloseWriter); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
