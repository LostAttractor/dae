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
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/sys/unix"
)

func RetrieveOriginalDest(oob []byte) netip.AddrPort {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			ip := msg.Data[4:8]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip)), port)
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			ip := msg.Data[8:24]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom16([16]byte(ip)), port)
		}
	}
	return netip.AddrPort{}
}

type Listener struct {
	tcpListener net.Listener
	packetConn  net.PacketConn
}

func registerListener(m *ebpf.Map, key uint32, conn syscall.Conn) error {
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
	if err := registerListener(r.shared["listen_socket_map"], 0, listener.tcpListener.(syscall.Conn)); err != nil {
		return fmt.Errorf("register TCP listener: %w", err)
	}
	if err := registerListener(r.shared["listen_socket_map"], 1, listener.packetConn.(syscall.Conn)); err != nil {
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
		for {
			select {
			case <-r.done:
				return
			default:
			}
			n, oobn, _, src, err := serveUdpConn.ReadMsgUDPAddrPort(buf, oob)
			if err != nil {
				reportIngressError(fmt.Errorf("read UDP datagram: %w", err))
				return
			}
			dst := RetrieveOriginalDest(oob[:oobn])

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
				r.udpEndpoints.deliverMITM(src, dst, endpoint.(*UdpEndpoint).firstIfindex, buf[:n])
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

func (r *Runtime) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	// Listen.
	var listenConfig = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
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
