/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

const maxConcurrentDnsUDPExchanges = 256

type udpDNSForwarder struct {
	dns.Upstream
	dialArgument dialArgument
	state        *dnsForwarderState
	mu           sync.Mutex
	connections  map[net.Conn]struct{}
	slots        chan struct{}
	closeDone    chan struct{}
	closeErr     error
	active       sync.WaitGroup
}

func (d *udpDNSForwarder) Close() error {
	d.mu.Lock()
	if !d.state.close() {
		d.mu.Unlock()
		return d.waitForShutdown()
	}
	connections := make([]net.Conn, 0, len(d.connections))
	for conn := range d.connections {
		connections = append(connections, conn)
	}
	d.connections = nil
	d.mu.Unlock()
	closeResults := make(chan error, len(connections))
	for _, conn := range connections {
		go func() { closeResults <- conn.Close() }()
	}
	go func() {
		var errs []error
		for range connections {
			if err := <-closeResults; err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		d.active.Wait()
		d.closeErr = errors.Join(errs...)
		close(d.closeDone)
	}()
	return d.waitForShutdown()
}

func (d *udpDNSForwarder) waitForShutdown() error {
	select {
	case <-d.closeDone:
		return d.closeErr
	case <-time.After(consts.DefaultDialTimeout):
		return fmt.Errorf("UDP exchange shutdown timeout: %w", context.DeadlineExceeded)
	}
}

func (d *udpDNSForwarder) beginExchange(ctx context.Context) (func(), bool) {
	d.mu.Lock()
	if d.state.isClosed() {
		d.mu.Unlock()
		return nil, false
	}
	d.active.Add(1)
	d.mu.Unlock()

	select {
	case d.slots <- struct{}{}:
	case <-ctx.Done():
		d.active.Done()
		return nil, false
	case <-d.state.ctx.Done():
		d.active.Done()
		return nil, false
	}

	return func() {
		<-d.slots
		d.active.Done()
	}, true
}

func (d *udpDNSForwarder) registerConnection(conn net.Conn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.isClosed() {
		return false
	}
	if d.connections == nil {
		d.connections = make(map[net.Conn]struct{})
	}
	d.connections[conn] = struct{}{}
	return true
}

func (d *udpDNSForwarder) releaseConnection(conn net.Conn) {
	go func() {
		_ = conn.Close()
		d.mu.Lock()
		delete(d.connections, conn)
		d.mu.Unlock()
	}()
}

func (d *udpDNSForwarder) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if err := validateDNSForwardQuery(msg, "UDP", true); err != nil {
		return err
	}
	parentCtx := ctx
	ctx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	ctx, cancelTimeout := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancelTimeout()
	endExchange, started := d.beginExchange(ctx)
	if !started {
		return dnsForwarderOperationError(parentCtx, d.state, ctx, net.ErrClosed)
	}
	defer endExchange()
	conn, err := d.dialArgument.dialerForConnection().DialContext(ctx, "udp", d.dialArgument.Target.String())
	if err != nil {
		return dnsForwarderOperationError(parentCtx, d.state, ctx, err)
	}
	if !d.registerConnection(conn) {
		closeInBackground(conn)
		return net.ErrClosed
	}
	defer d.releaseConnection(conn)

	wireQuery := msg.Copy()
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return fmt.Errorf("generate DNS transaction ID: %w", err)
	}
	originalID := msg.Id
	wireQuery.Id = binary.BigEndian.Uint16(randomID[:])
	if err := netutils.ResolveUDP(ctx, conn, wireQuery); err != nil {
		return dnsForwarderOperationError(parentCtx, d.state, ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	*msg = *wireQuery
	msg.Id = originalID
	return nil
}
