// Modified from https://github.com/nadoo/glider/tree/v0.16.2
package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
)

type PktConn struct {
	net.PacketConn
	ctrlConn    net.Conn
	server      *net.UDPAddr
	lease       *netproxy.Lease
	closeOnce   sync.Once
	closeErr    error
	controlDone chan struct{}
	leaseDone   chan struct{}
}

func NewPktConn(c net.PacketConn, ctrl net.Conn, server *net.UDPAddr) *PktConn {
	pc := &PktConn{PacketConn: c, ctrlConn: ctrl, server: server,
		lease:       netproxy.NewLease(netproxy.NewResourceRef(), netproxy.DependencyOf(c), netproxy.DependencyOf(ctrl)),
		controlDone: make(chan struct{}), leaseDone: make(chan struct{})}
	go func() {
		defer close(pc.controlDone)
		var b [1]byte
		for {
			_, err := ctrl.Read(b[:])
			if err == nil {
				continue
			}
			onlyTimeout := true
			for _, failure := range netproxy.Failures(err) {
				if failure.Reason != netproxy.ReasonDeadline || failure.Scope == netproxy.ScopeSharedResource {
					onlyTimeout = false
				}
			}
			if onlyTimeout {
				continue
			}
			if err == io.EOF {
				err = netproxy.WrapFailure(err, netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonClosed, Phase: netproxy.OpRead})
			}
			pc.shutdown(err)
			return
		}
	}()
	go func() {
		defer close(pc.leaseDone)
		<-pc.lease.Done()
		pc.shutdown(pc.lease.Cause())
	}()
	return pc
}

func (pc *PktConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !pc.lease.Valid() {
		return 0, nil, pc.lease.Cause()
	}
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	server := pc.server.AddrPort()
	var n int
	for {
		count, from, err := pc.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, errors.Join(err, pc.lease.Cause())
		}
		var source netip.AddrPort
		if udp, ok := from.(*net.UDPAddr); ok {
			source = udp.AddrPort()
		} else if from != nil {
			source, _ = netip.ParseAddrPort(from.String())
		}
		// Verify the outer relay before trusting the embedded reply address.
		if source.Port() == server.Port() && source.Addr().Unmap() == server.Addr().Unmap() {
			n = count
			break
		}
	}
	if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
		return 0, nil, netproxy.WrapFailure(fmt.Errorf("invalid SOCKS5 UDP reserved/fragment fields"), netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol, Phase: netproxy.OpRead})
	}
	reader := bytes.NewReader(buf[3:n])
	addr, err := ReadAddr(reader)
	if err != nil {
		return 0, nil, netproxy.WrapFailure(err, netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol, Phase: netproxy.OpRead})
	}
	payloadLen := reader.Len()
	copied := copy(b, buf[n-payloadLen:n])
	if copied < payloadLen {
		return copied, addr, io.ErrShortBuffer
	}
	return copied, addr, nil
}

func (pc *PktConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !pc.lease.Valid() {
		return 0, pc.lease.Cause()
	}
	if addr == nil {
		return 0, ErrInvalidAddress
	}
	target, err := socks.ParseAddr(addr.String())
	if err != nil {
		return 0, err
	}
	if 3+len(target)+len(b) > 65507 {
		return 0, fmt.Errorf("SOCKS5 UDP datagram exceeds 65507 bytes")
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write([]byte{0, 0, 0})
	buf.Write(target)
	buf.Write(b)
	n, err := pc.PacketConn.WriteTo(buf.Bytes(), pc.server)
	if n != buf.Len() {
		if err == nil {
			err = io.ErrShortWrite
		}
		return 0, errors.Join(err, pc.lease.Cause())
	}
	return len(b), err
}

func (pc *PktConn) shutdown(cause error) {
	pc.closeOnce.Do(func() {
		pc.lease.Invalidate(cause)
		pc.closeErr = errors.Join(pc.ctrlConn.Close(), pc.PacketConn.Close())
	})
}

func (pc *PktConn) Close() error {
	pc.shutdown(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Origin: netproxy.OriginLocalCleanup, Scope: netproxy.ScopeStream}))
	<-pc.controlDone
	<-pc.leaseDone
	return pc.closeErr
}

func (pc *PktConn) DependencyLease() *netproxy.Lease { return pc.lease }
