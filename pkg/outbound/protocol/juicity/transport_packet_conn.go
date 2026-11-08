package juicity

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
)

type TransportPacketConn struct {
	net.PacketConn
	proxyAddr *net.UDPAddr
	target    net.Addr
	key       *shadowsocks.Key
	firstIv   []byte
	mu        sync.Mutex
	lease     *netproxy.Lease
	authLease *netproxy.Lease
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Write reports a datagram dropped beneath as written, as a
// netproxy.NonBlockingWriter's WriteTo does.
func (c *TransportPacketConn) Write(b []byte) (int, error) { return c.write(b, true) }

// TryWriteTo sends the encrypted datagram to the proxy without waiting; see
// netproxy.NonBlockingWriter.
func (c *TransportPacketConn) TryWriteTo(b []byte, _ net.Addr) (int, error) {
	if !c.CanTryWrite() {
		return 0, errors.ErrUnsupported
	}
	return c.write(b, false)
}

// Without wait, write returns errors.ErrUnsupported if the socket beneath can
// only wait.
func (c *TransportPacketConn) write(b []byte, wait bool) (int, error) {
	if c.lease != nil && !c.lease.Valid() {
		return 0, c.lease.Cause()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var salt []byte
	if c.firstIv != nil {
		salt = c.firstIv
	} else {
		salt = pool.GetBuffer(c.key.CipherConf.SaltLen)
		defer pool.PutBuffer(salt)
		salt[0] = 0
		salt[1] = 0
		rand.Read(salt[2:])
	}
	toWrite, err := EncryptUDPFromPool(c.key, b, salt, ciphers.JuicityReusedInfo)
	if err != nil {
		return 0, err
	}
	defer pool.PutBuffer(toWrite)
	_, err = netproxy.TryWriteTo(c.PacketConn, toWrite, c.proxyAddr)
	if wait && errors.Is(err, errors.ErrUnsupported) {
		_, err = c.PacketConn.WriteTo(toWrite, c.proxyAddr)
	}
	switch {
	case errors.Is(err, netproxy.ErrPacketDropped):
		// The next datagram carries firstIv instead.
		if wait {
			return len(b), nil
		}
		return 0, err
	case errors.Is(err, errors.ErrUnsupported):
		return 0, err
	case err != nil:
		return 0, c.wrap(err)
	}
	c.firstIv = nil
	return len(b), nil
}

func (c *TransportPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *TransportPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := pool.GetBuffer(65535 + CipherConf.SaltLen + CipherConf.TagLen)
	defer pool.PutBuffer(buf)
	for {
		n, _, err = c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, c.wrap(err)
		}
		if n, err = DecryptUDP(buf[CipherConf.SaltLen:], c.key, buf[:n], ciphers.JuicityReusedInfo); err == nil {
			return copy(p, buf[CipherConf.SaltLen:CipherConf.SaltLen+n]), c.target, nil
		}
		// The socket is unconnected, so anyone may send to it; only an
		// authenticated datagram belongs to the association.
		dropUnauthenticated.Add(1)
	}
}

var dropUnauthenticated = netproxy.NewDrop("juicity", netproxy.DropDownload, "unauthenticated")

func (c *TransportPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *TransportPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.authLease != nil {
			c.authLease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.authLease.Resource(), Stream: c.authLease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerUDP, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
		}
		if c.lease != nil {
			c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerUDP, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
		}
		if c.done != nil {
			close(c.done)
		}
		c.closeErr = c.PacketConn.Close()
	})
	return c.closeErr
}
func (c *TransportPacketConn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *TransportPacketConn) wrap(err error) error {
	if c.lease != nil && !c.lease.Valid() {
		return c.lease.Cause()
	}
	return err
}

func (c *TransportPacketConn) LocalAddr() net.Addr  { return c.PacketConn.LocalAddr() }
func (c *TransportPacketConn) RemoteAddr() net.Addr { return c.target }

// CanTryWrite reports the carrier capability without bypassing this layer.
func (c *TransportPacketConn) CanTryWrite() bool { return netproxy.CanTryWriteTo(c.PacketConn) }
