package vless

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Conn removes the one client response header without buffering payload bytes.
// Exact reads let Vision safely hand its TLS carrier over to direct mode.
type Conn struct {
	net.Conn
	readMu, writeMu   sync.Mutex
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	n, err := c.Conn.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeErr = err
	}
	return n, err
}
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	c.writeErr = net.ErrClosed
	if writer, ok := c.Conn.(netproxy.CloseWriter); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
