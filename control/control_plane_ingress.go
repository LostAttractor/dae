/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type Listener struct {
	tcpListener net.Listener
	packetConn  net.PacketConn
}

// controlPlaneIngress owns only the duplicated descriptors used by one plane.
// The original Listener remains open across reloads so packets can queue for
// the successor after these descriptors are closed.
type controlPlaneIngress struct {
	tcp, udp ingressSockets
	loops    sync.WaitGroup
}

type ingressSockets struct {
	closeOnce  sync.Once
	closeErr   error
	closeFuncs []func() error
}

func (i *controlPlaneIngress) close() error {
	return errors.Join(i.tcp.close(), i.udp.close())
}

func (i *ingressSockets) close() error {
	i.closeOnce.Do(func() {
		var errs []error
		for j := len(i.closeFuncs) - 1; j >= 0; j-- {
			if err := i.closeFuncs[j](); err != nil {
				errs = append(errs, err)
			}
		}
		i.closeErr = errors.Join(errs...)
	})
	return i.closeErr
}

func (c *ControlPlane) openIngress(listener *Listener) (tcpListener net.Listener, serveUdpConn *net.UDPConn, ingress *controlPlaneIngress, err error) {
	c.ingressMu.Lock()
	defer c.ingressMu.Unlock()
	if c.ingressRetired {
		return nil, nil, nil, net.ErrClosed
	}
	if c.ingress != nil {
		return nil, nil, nil, errors.New("control plane ingress is already open")
	}

	ingress = new(controlPlaneIngress)
	ownedIngress := ingress
	defer func() {
		if err != nil {
			_ = ownedIngress.close()
		}
	}()

	tcpFile, err := listener.tcpListener.(*net.TCPListener).File()
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to retrieve copy of the underlying TCP connection file")
	}
	ingress.tcp.closeFuncs = append(ingress.tcp.closeFuncs, tcpFile.Close)
	if err = c.core.bpf.ListenSocketMap.Update(uint32(0), uint64(tcpFile.Fd()), ebpf.UpdateAny); err != nil {
		return nil, nil, nil, oops.Errorf("failed to register the TCP listener: %w", err)
	}
	tcpListener, err = net.FileListener(tcpFile)
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to duplicate the TCP listener: %w", err)
	}
	ingress.tcp.closeFuncs = append(ingress.tcp.closeFuncs, tcpListener.Close)

	udpFile, err := listener.packetConn.(*net.UDPConn).File()
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to retrieve copy of the underlying UDP connection file")
	}
	ingress.udp.closeFuncs = append(ingress.udp.closeFuncs, udpFile.Close)
	if err = c.core.bpf.ListenSocketMap.Update(uint32(1), uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
		return nil, nil, nil, oops.Errorf("failed to register the UDP listener: %w", err)
	}
	udpPacketConn, err := net.FilePacketConn(udpFile)
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to duplicate the UDP socket: %w", err)
	}
	ingress.udp.closeFuncs = append(ingress.udp.closeFuncs, udpPacketConn.Close)
	serveUdpConn = udpPacketConn.(*net.UDPConn)

	// Register both loops before publishing ingress. Close may run as soon as
	// this function unlocks and must not race a zero-count Wait with Add.
	ingress.loops.Add(2)
	c.ingress = ingress
	return tcpListener, serveUdpConn, ingress, nil
}

func (c *ControlPlane) closeIngress() (*controlPlaneIngress, error) {
	return c.retireIngress(false)
}

func (c *ControlPlane) retireIngress(keepUDP bool) (*controlPlaneIngress, error) {
	c.ingressMu.Lock()
	c.ingressRetired = true
	c.udpDraining.Store(true)
	ingress := c.ingress
	c.ingressMu.Unlock()
	if ingress == nil {
		return nil, nil
	}
	if keepUDP {
		return ingress, ingress.tcp.close()
	}
	return ingress, ingress.close()
}

func (l *Listener) Close() error {
	var (
		err  error
		err2 error
	)
	if err, err2 = l.tcpListener.Close(), l.packetConn.Close(); err2 != nil {
		if err == nil {
			err = err2
		} else {
			err = oops.Errorf("%w: %v", err, err2)
		}
	}
	return err
}

func (c *ControlPlane) Serve(readyChan chan<- bool, listener *Listener) (err error) {
	sentReady := false
	defer func() {
		if !sentReady {
			readyChan <- false
		}
	}()
	// Serve on duplicates of the shared listener sockets. Retirement stops TCP
	// acceptance first; UDP delivery remains available for QUIC shutdown.
	tcpListener, serveUdpConn, ingress, err := c.openIngress(listener)
	if err != nil {
		return err
	}

	go func() {
		defer ingress.loops.Done()
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			lconn, err := tcpListener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Errorf("%+v", oops.Wrapf(err, "Error when accept"))
				}
				break
			}
			if !c.tcpConnections.beginSetup(lconn) {
				continue
			}
			go serveTCPConnection(c, lconn, c.tcpSetupCtx, c.tcpConnections)
		}
	}()
	go func() {
		defer ingress.loops.Done()
		buf := pool.GetBuffer(consts.EthernetMtu)
		oob := pool.GetBuffer(120)
		defer pool.PutBuffer(buf)
		defer pool.PutBuffer(oob)
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			n, oobn, _, src, err := serveUdpConn.ReadMsgUDPAddrPort(buf, oob)
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Errorf("%+v", oops.Wrapf(err, "ReadFromUDPAddrPort: %v", src.String()))
				}
				break
			}
			dst := RetrieveOriginalDest(oob[:oobn])

			src = common.ConvergeAddrPort(src)
			dst = common.ConvergeAddrPort(dst)
			if c.udpDraining.Load() {
				// No DNS work, sniffing, routing decisions or new associations
				// during retirement. Existing QUIC sessions still need client
				// ACKs and stream data to complete graceful shutdown.
				if result, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_UDP); err == nil {
					c.udpEndpoints.deliverMITM(src, dst, result.Ifindex, buf[:n])
				}
				continue
			}

			// Snapshot the first packet before another packet replaces the handoff.
			// Existing sources already own their route.
			var routingResult *bpfRoutingResult
			if _, exists := c.udpEndpoints.pool.Load(src); !exists {
				routingResult, err = c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_UDP)
				if err != nil {
					log.Warnf("UDP routing handoff: %v", err)
					continue
				}
			}

			c.enqueueUDPPacket(buf[:n], src, dst, routingResult)
		}
	}()
	sentReady = true
	readyChan <- true
	<-c.ctx.Done()
	return nil
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	// Listen.
	var listenConfig = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	listenAddr := net.JoinHostPort("", strconv.Itoa(int(port)))
	tcpListener, err := listenConfig.Listen(context.TODO(), "tcp", listenAddr)
	if err != nil {
		return nil, oops.Errorf("listenTCP: %w", err)
	}
	packetConn, err := listenConfig.ListenPacket(context.TODO(), "udp", listenAddr)
	if err != nil {
		_ = tcpListener.Close()
		return nil, oops.Errorf("listenUDP: %w", err)
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
	if err = c.Serve(readyChan, listener); err != nil {
		return nil, oops.Errorf("failed to serve: %w", err)
	}

	return listener, nil
}
