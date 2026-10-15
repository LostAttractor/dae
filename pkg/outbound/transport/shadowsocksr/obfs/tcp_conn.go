package obfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type Conn struct {
	net.Conn
	codec                    IObfs
	cipher                   *ciphers.StreamCipher
	addrLen                  int
	initialized              bool
	readMu, writeMu, codecMu sync.Mutex
	pending                  bytes.Buffer
	readErr, writeErr        error
	closed                   atomic.Bool
	writeClosed              bool
	closeOnce                sync.Once
	closeErr                 error
}

// The enclosing cipher sets these before handing the connection to callers.
func (c *Conn) SetCipher(cipher *ciphers.StreamCipher) { c.cipher = cipher }
func (c *Conn) SetAddrLen(length int)                  { c.addrLen = length }
func (c *Conn) DependencyLease() *netproxy.Lease       { return netproxy.DependencyOf(c.Conn) }

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
		if n == 0 {
			if err == nil {
				empty++
				if empty == 100 {
					c.readErr = io.ErrNoProgress
				}
			}
			continue
		}
		c.codecMu.Lock()
		decoded, sendBack, decodeErr := c.codec.Decode(buf[:n])
		if decodeErr == nil {
			c.pending.Write(decoded)
		}
		c.codecMu.Unlock()
		if decodeErr != nil {
			c.readErr = netproxy.WrapFailure(decodeErr, netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Phase: netproxy.OpRead, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
			_ = c.Conn.Close()
		} else if sendBack {
			if _, err := c.Write(nil); err != nil {
				c.readErr = err
			}
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.write(p)
}

func (c *Conn) write(p []byte) (int, error) {
	if c.closed.Load() || c.writeClosed {
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	c.codecMu.Lock()
	if !c.initialized {
		if c.cipher == nil {
			c.codecMu.Unlock()
			return 0, fmt.Errorf("SSR obfuscation has no cipher")
		}
		info := c.codec.GetServerInfo()
		info.IVLen, info.Key, info.AddrLen = c.cipher.InfoIVLen(), c.cipher.Key(), c.addrLen
		c.codec.SetServerInfo(info)
		c.initialized = true
	}
	encoded, err := c.codec.Encode(p)
	if err == nil {
		buf.Write(encoded)
	}
	c.codecMu.Unlock()
	if err == nil && buf.Len() == 0 {
		return len(p), nil
	}
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

// Handshake flushes the initial encrypted target before the SSR dialer hands
// the connection to callers. Only the authenticated/opaque peer preface is read;
// any coalesced application bytes remain available to Read.
func (c *Conn) Handshake() error {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	pending := false
	switch codec := c.codec.(type) {
	case *randomHead:
		pending = !codec.rawTransSent
	case *tls12TicketAuth:
		pending = codec.handshakeStatus != 8
	}
	if !pending {
		return nil
	}
	buf := pool.GetBuffer(4096)
	defer pool.PutBuffer(buf)
	for empty := 0; ; {
		n, err := c.Conn.Read(buf)
		if n > 0 {
			decoded, sendBack, decodeErr := c.codec.Decode(buf[:n])
			if decodeErr != nil {
				return netproxy.WrapFailure(decodeErr, netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Phase: netproxy.OpHandshake, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
			}
			c.pending.Write(decoded)
			if sendBack {
				_, writeErr := c.write(nil)
				return errors.Join(err, writeErr)
			}
		} else {
			empty++
			if empty == 100 && err == nil {
				err = io.ErrNoProgress
			}
		}
		if err != nil {
			return err
		}
	}
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
	// A peer handshake may still be holding application bytes in the codec.
	// Report unsupported until they have been flushed, never send an early FIN.
	c.codecMu.Lock()
	pending := false
	switch codec := c.codec.(type) {
	case *randomHead:
		pending = !codec.rawTransSent
	case *tls12TicketAuth:
		pending = codec.handshakeStatus != 8
	}
	c.codecMu.Unlock()
	if pending {
		return errors.ErrUnsupported
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
		c.pending = bytes.Buffer{}
		c.readMu.Unlock()
	})
	return c.closeErr
}
