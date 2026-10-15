// Modified from https://github.com/nadoo/glider/tree/v0.16.2
package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
)

const (
	replyCommandNotSupported     = 7
	replyAddressTypeNotSupported = 8
)

func (s *Socks5) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		c, err := s.ParentDialer.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 dial proxy: %w", err)
		}
		if err := protocol.Handshake(ctx, c, func() error { _, err := s.connect(c, address, socks.CmdConnect); return err }); err != nil {
			return nil, err
		}
		return c, nil
	case "udp":
		c, err := s.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: c, Address: netproxy.NewAddr("udp", address)}, nil
	default:
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Socks5) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	ctrl, err := s.ParentDialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial proxy: %w", err)
	}
	var bound socks.Addr
	if err := protocol.Handshake(ctx, ctrl, func() error {
		// This request names the client's UDP source, which is not yet known.
		bound, err = s.connect(ctrl, "0.0.0.0:0", socks.CmdUDPAssociate)
		return err
	}); err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = ctrl.Close()
		}
	}()
	host, port, err := net.SplitHostPort(bound.String())
	if err != nil {
		return nil, fmt.Errorf("socks5 invalid bind address: %w", err)
	}
	if port == "0" {
		return nil, fmt.Errorf("socks5 returned zero UDP relay port")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host, _, err = net.SplitHostPort(s.addr)
		if err != nil {
			return nil, err
		}
	}
	relay := net.JoinHostPort(host, port)
	conn, err := s.ParentDialer.ListenPacket(ctx, relay)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial UDP relay: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	pc := NewPktConn(conn, ctrl, netproxy.NewAddr("udp", relay))
	handedOff = true
	if !pc.lease.Valid() {
		_ = pc.Close()
		return nil, pc.lease.Cause()
	}
	return pc, nil
}

func handshakeFailure(err error, origin netproxy.FailureOrigin, reason netproxy.FailureReason, code byte) error {
	return netproxy.WrapFailure(err, netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Phase: netproxy.OpHandshake, Origin: origin, Reason: reason, Code: strconv.Itoa(int(code))})
}

func writeHandshake(conn net.Conn, b []byte) error {
	n, err := conn.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("socks5 write handshake: %w", err)
	}
	return nil
}

func (s *Socks5) connect(conn net.Conn, target string, cmd byte) (socks.Addr, error) {
	address, err := socks.ParseAddr(target)
	if err != nil {
		return nil, err
	}
	authenticated := len(s.user) > 0
	if len(s.user) > 255 || len(s.password) > 255 || (authenticated && len(s.password) == 0) {
		return nil, fmt.Errorf("socks5 username/password must contain 1 to 255 bytes")
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write([]byte{Version, 1, socks.AuthNone})
	if authenticated {
		buf.Bytes()[1] = 2
		buf.WriteByte(socks.AuthPassword)
	}
	if err := writeHandshake(conn, buf.Bytes()); err != nil {
		return nil, err
	}
	var reply [3]byte
	if _, err := io.ReadFull(conn, reply[:2]); err != nil {
		return nil, fmt.Errorf("socks5 read method: %w", err)
	}
	if reply[0] != Version {
		return nil, handshakeFailure(fmt.Errorf("socks5 invalid method version %d", reply[0]), netproxy.OriginPeer, netproxy.ReasonProtocol, reply[0])
	}
	switch reply[1] {
	case socks.AuthNone:
	case socks.AuthPassword:
		if !authenticated {
			return nil, handshakeFailure(fmt.Errorf("socks5 selected unoffered password method"), netproxy.OriginPeer, netproxy.ReasonAuth, reply[1])
		}
		buf.Reset()
		buf.WriteByte(1)
		buf.WriteByte(byte(len(s.user)))
		buf.WriteString(s.user)
		buf.WriteByte(byte(len(s.password)))
		buf.WriteString(s.password)
		if err := writeHandshake(conn, buf.Bytes()); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, reply[:2]); err != nil {
			return nil, fmt.Errorf("socks5 read authentication: %w", err)
		}
		if reply[0] != 1 {
			return nil, handshakeFailure(fmt.Errorf("socks5 invalid authentication version %d", reply[0]), netproxy.OriginPeer, netproxy.ReasonProtocol, reply[0])
		}
		if reply[1] != 0 {
			return nil, handshakeFailure(fmt.Errorf("socks5 rejected username/password"), netproxy.OriginPeer, netproxy.ReasonAuth, reply[1])
		}
	default:
		return nil, handshakeFailure(fmt.Errorf("socks5 unsupported selected method %d", reply[1]), netproxy.OriginPeer, netproxy.ReasonAuth, reply[1])
	}
	buf.Reset()
	buf.Write([]byte{Version, cmd, 0})
	buf.Write(address)
	if err := writeHandshake(conn, buf.Bytes()); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, fmt.Errorf("socks5 read reply: %w", err)
	}
	if reply[0] != Version || reply[2] != 0 {
		return nil, handshakeFailure(fmt.Errorf("socks5 invalid reply version/reserved field"), netproxy.OriginPeer, netproxy.ReasonProtocol, reply[0])
	}
	if reply[1] != 0 {
		message := fmt.Sprintf("reply %d", reply[1])
		if int(reply[1]) < len(socks.Errors) {
			message = socks.Errors[reply[1]].Error()
		}
		err := fmt.Errorf("socks5 request rejected: %s", message)
		origin := netproxy.OriginTarget
		if reply[1] == replyCommandNotSupported || reply[1] == replyAddressTypeNotSupported {
			err = fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, err)
			origin = netproxy.OriginPeer
		}
		return nil, handshakeFailure(err, origin, netproxy.ReasonRejected, reply[1])
	}
	bound, err := socks.ReadAddr(conn)
	if err != nil {
		return nil, fmt.Errorf("socks5 read bind address: %w", err)
	}
	return bound, nil
}
