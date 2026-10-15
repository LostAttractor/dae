package juicity

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

type PacketConn struct {
	*Conn
	readMu sync.Mutex
}

func (c *PacketConn) Write(b []byte) (int, error) {
	return c.writeTo(b, net.JoinHostPort(c.Metadata.Hostname, strconv.Itoa(int(c.Metadata.Port))))
}
func (c *PacketConn) Read(b []byte) (int, error) { n, _, err := c.ReadFrom(b); return n, err }
func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	defer func() {
		if err == nil || err == io.EOF {
			return
		}
		failure := netproxy.ClassifyFailure(err)
		if failure.Scope == netproxy.ScopeUnknown {
			err = netproxy.WrapFailure(err, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Phase: netproxy.OpRead, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
			c.lease.Invalidate(err)
			_ = c.Close()
		}
	}()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	m, err := readMetadata(c.Conn)
	if err != nil {
		return 0, nil, err
	}
	var header [2]byte
	if _, err = io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	n, err = io.ReadFull(c.Conn, p[:min(len(p), length)])
	if err == nil && length > n {
		_, err = io.CopyN(io.Discard, c.Conn, int64(length-n))
	}
	return n, netproxy.NewAddr("udp", net.JoinHostPort(m.Hostname, strconv.Itoa(int(m.Port)))), err
}
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("nil packet destination")
	}
	return c.writeTo(p, addr.String())
}
func (c *PacketConn) writeTo(p []byte, addr string) (int, error) {
	if len(p) > 65535 {
		return 0, fmt.Errorf("Juicity UDP payload exceeds 65535 bytes")
	}
	metadata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	m := Metadata{Metadata: metadata, Network: "udp"}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err = m.appendTo(buf); err != nil {
		return 0, err
	}
	buf.Write(binary.BigEndian.AppendUint16(nil, uint16(len(p))))
	buf.Write(p)
	if _, err = c.Conn.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}
