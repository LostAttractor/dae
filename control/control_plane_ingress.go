/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"golang.org/x/sys/unix"
)

// RetrieveOriginalDest reads IP(V6)_ORIGDSTADDR in place: every ingress
// datagram passes here, and the control messages need no copy. Like
// syscall.ParseSocketControlMessage, a header beyond the received bytes
// rejects the whole buffer.
func RetrieveOriginalDest(oob []byte) (destination netip.AddrPort) {
	for len(oob) >= unix.CmsgLen(0) {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if header.Len < unix.SizeofCmsghdr || uint64(header.Len) > uint64(len(oob)) {
			return netip.AddrPort{}
		}
		data := oob[unix.CmsgLen(0):header.Len]
		if !destination.IsValid() {
			if header.Level == unix.SOL_IP && header.Type == unix.IP_RECVORIGDSTADDR && len(data) >= unix.SizeofSockaddrInet4 {
				destination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[4:8])), binary.BigEndian.Uint16(data[2:4]))
			} else if header.Level == unix.SOL_IPV6 && header.Type == unix.IPV6_RECVORIGDSTADDR && len(data) >= unix.SizeofSockaddrInet6 {
				destination = netip.AddrPortFrom(netip.AddrFrom16([16]byte(data[8:24])), binary.BigEndian.Uint16(data[2:4]))
			}
		}
		oob = oob[min(unix.CmsgSpace(len(data)), len(oob)):]
	}
	return destination
}

// socketDrops reads SO_RXQ_OVFL: the datagrams the socket dropped before it
// queued this one, counted since its creation; zero until the first drop.
func socketDrops(oob []byte) uint32 {
	for len(oob) >= unix.CmsgLen(0) {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if header.Len < unix.SizeofCmsghdr || uint64(header.Len) > uint64(len(oob)) {
			return 0
		}
		data := oob[unix.CmsgLen(0):header.Len]
		if header.Level == unix.SOL_SOCKET && header.Type == unix.SO_RXQ_OVFL && len(data) >= 4 {
			return binary.NativeEndian.Uint32(data)
		}
		oob = oob[min(unix.CmsgSpace(len(data)), len(oob)):]
	}
	return 0
}

// countIngressDrops counts what a read reports: the datagrams the socket
// dropped since the total it last reported, and the datagram itself if it was
// truncated, in which case it is not delivered. A read without the total
// (none yet, or truncated control data) reports no drops.
func countIngressDrops(oob []byte, flags int, dropped *uint32) (truncated bool) {
	if total := socketDrops(oob); total != 0 && total != *dropped {
		dropSocketOverflow.Add(uint64(total - *dropped))
		*dropped = total
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		dropTruncated.Add(1)
		return true
	}
	return false
}

type Listener struct {
	tcpListener net.Listener
	packetConn  net.PacketConn
}

// registerSocket borrows the fd; the kernel removes its map references on close.
func registerSocket(m *ebpf.Map, key any, conn syscall.Conn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var updateErr error
	err = raw.Control(func(fd uintptr) { updateErr = m.Update(key, uint64(fd), ebpf.UpdateAny) })
	return errors.Join(err, updateErr)
}

func (r *Runtime) openIngress(listener *Listener) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		return net.ErrClosed
	default:
	}
	if r.listener != nil {
		return errors.New("runtime ingress is already open")
	}
	if err := registerSocket(r.shared["listen_socket_map"], uint32(0), listener.tcpListener.(syscall.Conn)); err != nil {
		return fmt.Errorf("register TCP listener: %w", err)
	}
	if err := registerSocket(r.shared["listen_socket_map"], uint32(1), listener.packetConn.(syscall.Conn)); err != nil {
		return fmt.Errorf("register UDP listener: %w", err)
	}

	// Register both loops before publishing ingress. Close may run as soon as
	// this function unlocks and must not race a zero-count Wait with Add.
	r.ingress.Add(2)
	r.listener = listener
	return nil
}

func (l *Listener) Close() error {
	return errors.Join(l.tcpListener.Close(), l.packetConn.Close())
}

// Admission and retirement share mu. The handoff is consumed exactly once;
// its outbound IDs are interpreted only by the configuration that produced it.
func (r *Runtime) admitTCP(conn net.Conn) (*ControlPlane, *routingResult) {
	src, dst := conn.RemoteAddr().(*net.TCPAddr).AddrPort(), conn.LocalAddr().(*net.TCPAddr).AddrPort()
	result, err := retrieveRoutingResult(r.shared["routing_tuples_map"], src, dst, unix.IPPROTO_TCP)
	if err == nil {
		// This index is optional: failed registration retains the namespace lookup.
		_ = registerSocket(r.shared["tcp_proxy_socket_map"], tuplesKey(src, dst, unix.IPPROTO_TCP), conn.(syscall.Conn))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		if c := r.planes[result.Generation]; c != nil && c.tcpConnections.beginSetup(conn) {
			return c, result
		}
	}
	setTCPResetOnClose(conn)
	_ = conn.Close()
	return nil, nil
}

func (r *Runtime) Serve(readyChan chan<- bool, listener *Listener) (err error) {
	sentReady := false
	defer func() {
		if !sentReady {
			readyChan <- false
		}
	}()
	if err := r.openIngress(listener); err != nil {
		return err
	}
	tcpListener, serveUdpConn := listener.tcpListener, listener.packetConn.(*net.UDPConn)

	ingressErrors := make(chan error, 2)
	reportIngressError := func(err error) {
		select {
		case <-r.done:
		default:
			ingressErrors <- err
		}
	}
	go func() {
		defer r.ingress.Done()
		for {
			select {
			case <-r.done:
				return
			default:
			}
			lconn, err := tcpListener.Accept()
			if err != nil {
				reportIngressError(fmt.Errorf("accept TCP connection: %w", err))
				return
			}
			c, result := r.admitTCP(lconn)
			if c == nil {
				continue
			}
			go serveTCPConnection(c, lconn, c.tcpSetupCtx, c.tcpConnections, result)
		}
	}()
	go func() {
		defer r.ingress.Done()
		buf := pool.GetBuffer(udpReceiveBufferSize)
		oob := pool.GetBuffer(120)
		defer pool.PutBuffer(buf)
		defer pool.PutBuffer(oob)
		var dropped uint32 // by the socket, as last reported
		for {
			select {
			case <-r.done:
				return
			default:
			}
			n, oobn, flags, src, err := serveUdpConn.ReadMsgUDPAddrPort(buf, oob)
			if err != nil {
				reportIngressError(fmt.Errorf("read UDP datagram: %w", err))
				return
			}
			if countIngressDrops(oob[:oobn], flags, &dropped) {
				continue
			}
			dst := RetrieveOriginalDest(oob[:oobn])
			if !src.IsValid() || !dst.IsValid() {
				continue
			}

			src = common.ConvergeAddrPort(src)
			dst = common.ConvergeAddrPort(dst)
			// Snapshot the first packet before another packet replaces the handoff.
			// Existing sources already own their route.
			var routingResult *routingResult
			endpoint, exists := r.udpEndpoints.pool.Load(src)
			var owner *ControlPlane
			if exists {
				owner = endpoint.(*UdpEndpoint).setupOwner.Load()
			}
			if !exists || dst.Port() == 53 {
				routingResult, err = retrieveRoutingResult(r.shared["routing_tuples_map"], src, dst, unix.IPPROTO_UDP)
				if err != nil {
					dropRouteMissing.Add(1)
					continue
				}
			}
			r.mu.Lock()
			c := r.current
			if owner != nil {
				c = r.planes[owner.routingGeneration]
			}
			if routingResult != nil {
				c = r.planes[routingResult.Generation]
			}
			if c != nil && c.udpDraining.Load() && exists {
				r.mu.Unlock()
				ue := endpoint.(*UdpEndpoint)
				if (dst.Port() != 53 || routingResult.Must != 0) && ue.acceptsRoutingSource(routingResult) {
					r.udpEndpoints.deliverMITM(src, dst, ue.firstIfindex, buf[:n])
				}
				continue
			}
			if c != nil {
				c.enqueueUDPPacket(buf[:n], src, dst, routingResult)
			}
			r.mu.Unlock()
		}
	}()
	sentReady = true
	readyChan <- true
	select {
	case err := <-ingressErrors:
		return err
	case err := <-r.errors:
		return err
	case <-r.done:
		return nil
	}
}

// tproxyListenConfig creates the transparent listeners. It declares TCP:
// Go listeners default to MPTCP since Go 1.24, but SOCKMAP and
// bpf_sk_assign accept only IPPROTO_TCP sockets. An accepted TCP socket
// that dae closes before the client has closed its side resets the client
// once dae's FIN is acknowledged (TCP_LINGER2 < 0), instead of leaving it open.
// The UDP socket reports its receive queue's drops with each datagram.
func tproxyListenConfig() net.ListenConfig {
	config := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error {
		if err := tproxyControl(c); err != nil {
			return err
		}
		level, option, value := unix.IPPROTO_TCP, unix.TCP_LINGER2, -1
		if !strings.HasPrefix(network, "tcp") {
			level, option, value = unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1
		}
		var err error
		if controlErr := c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), level, option, value)
		}); controlErr != nil {
			return controlErr
		}
		return err
	}}
	config.SetMultipathTCP(false)
	return config
}

func (r *Runtime) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	listenConfig := tproxyListenConfig()
	listenAddr := net.JoinHostPort("", strconv.Itoa(int(port)))
	tcpListener, err := listenConfig.Listen(context.TODO(), "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listenTCP: %w", err)
	}
	packetConn, err := listenConfig.ListenPacket(context.TODO(), "udp", listenAddr)
	if err != nil {
		_ = tcpListener.Close()
		return nil, fmt.Errorf("listenUDP: %w", err)
	}
	listener = &Listener{
		tcpListener: tcpListener,
		packetConn:  packetConn,
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	// Serve
	if err = r.Serve(readyChan, listener); err != nil {
		return nil, fmt.Errorf("failed to serve: %w", err)
	}

	return listener, nil
}
