package proto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type Conn struct {
	net.Conn
	codec                    IProtocol
	readMu, writeMu, codecMu sync.Mutex
	encoded, pending         bytes.Buffer
	readErr, writeErr        error
	writeClosed              bool
	closed                   atomic.Bool
	closeOnce                sync.Once
	closeErr                 error
}

func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	buf := pool.GetBuffer(4096)
	defer pool.PutBuffer(buf)
	for empty := 0; ; {
		if c.pending.Len() > 0 {
			return c.pending.Read(p)
		}
		if c.readErr != nil {
			err := c.readErr
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				c.readErr = nil
			}
			return 0, err
		}
		n, err := c.Conn.Read(buf)
		c.readErr = err
		if n == 0 && err == nil {
			empty++
			if empty == 100 {
				c.readErr = io.ErrNoProgress
			}
			continue
		}
		c.encoded.Write(buf[:n])
		c.codecMu.Lock()
		consumed, decodeErr := c.codec.Decode(c.encoded.Bytes(), &c.pending)
		c.codecMu.Unlock()
		if consumed < 0 || consumed > c.encoded.Len() {
			decodeErr = errors.New("invalid SSR frame length")
		}
		if decodeErr == nil {
			c.encoded.Next(consumed)
		}
		if decodeErr == nil && c.encoded.Len() > 8192 {
			decodeErr = errors.New("SSR frame exceeds maximum size")
		}
		if decodeErr != nil {
			c.readErr = netproxy.WrapFailure(decodeErr, netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Phase: netproxy.OpRead, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
			_ = c.Conn.Close()
		} else if err == io.EOF && c.encoded.Len() != 0 {
			c.readErr = io.ErrUnexpectedEOF
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() || c.writeClosed {
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	c.codecMu.Lock()
	err := c.codec.Encode(p, buf)
	c.codecMu.Unlock()
	if err == nil {
		var n int
		n, err = c.Conn.Write(buf.Bytes())
		if n != buf.Len() && err == nil {
			err = io.ErrShortWrite
		}
		if n == buf.Len() {
			c.writeErr = err
			return len(p), err
		}
	}
	c.writeErr = err
	return 0, err
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.writeClosed {
		return nil
	}
	cw, ok := c.Conn.(netproxy.CloseWriter)
	if !ok {
		return errors.ErrUnsupported
	}
	err := cw.CloseWrite()
	if err == nil {
		c.writeClosed = true
	}
	return err
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = c.Conn.Close()
		c.readMu.Lock()
		c.encoded, c.pending = bytes.Buffer{}, bytes.Buffer{}
		c.readMu.Unlock()
	})
	return c.closeErr
}
