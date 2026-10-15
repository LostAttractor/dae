package simpleobfs

import (
	"errors"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"io"
	"net"
)

func (c *HTTPObfs) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *TLSObfs) DependencyLease() *netproxy.Lease  { return netproxy.DependencyOf(c.Conn) }
func isTimeout(err error) bool {
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}
func wireError(message string) error {
	return netproxy.WrapFailure(errors.New("simple-obfs: "+message), netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
}
func writeWire(conn net.Conn, p []byte) error {
	n, err := conn.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return err
}
func (c *HTTPObfs) CloseWrite() error {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	cw, ok := c.Conn.(netproxy.CloseWriter)
	if !ok {
		return errors.ErrUnsupported
	}
	err := cw.CloseWrite()
	if err == nil {
		c.writeErr = net.ErrClosed
	}
	return err
}
func (c *TLSObfs) CloseWrite() error {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	cw, ok := c.Conn.(netproxy.CloseWriter)
	if !ok {
		return errors.ErrUnsupported
	}
	err := cw.CloseWrite()
	if err == nil {
		c.writeErr = net.ErrClosed
	}
	return err
}
