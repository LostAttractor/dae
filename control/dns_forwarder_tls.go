/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type dnsTLSExchange struct {
	conn      net.Conn
	closeOnce sync.Once
}

func (e *dnsTLSExchange) close() {
	e.closeOnce.Do(func() { _ = e.conn.Close() })
}

type tlsDNSForwarder struct {
	dns.Upstream
	dialArgument dialArgument
	state        *dnsForwarderState
	mu           sync.Mutex
	exchanges    map[*dnsTLSExchange]struct{}
	workers      sync.WaitGroup
}

func (d *tlsDNSForwarder) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if err := validateDNSForwardQuery(msg, "DoT", true); err != nil {
		return err
	}
	d.mu.Lock()
	if d.state.isClosed() {
		d.mu.Unlock()
		return net.ErrClosed
	}
	d.workers.Add(1)
	d.mu.Unlock()
	workerStarted := false
	defer func() {
		if !workerStarted {
			d.workers.Done()
		}
	}()

	forwardCtx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	dialCtx, cancelDial := context.WithTimeout(forwardCtx, consts.DefaultDialTimeout)
	conn, err := d.dialArgument.dialerForConnection().DialContext(dialCtx, "tcp", d.dialArgument.Target.String())
	if err != nil {
		err = dnsForwarderOperationError(ctx, d.state, dialCtx, err)
	} else {
		err = dnsForwarderOperationError(ctx, d.state, forwardCtx, nil)
	}
	cancelDial()
	if err != nil {
		if conn != nil {
			workerStarted = true
			go func() {
				defer d.workers.Done()
				_ = conn.Close()
			}()
		}
		return err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	exchange := &dnsTLSExchange{conn: conn}
	d.mu.Lock()
	if d.state.isClosed() {
		d.mu.Unlock()
		workerStarted = true
		go func() {
			defer d.workers.Done()
			_ = conn.Close()
		}()
		return net.ErrClosed
	}
	if d.exchanges == nil {
		d.exchanges = make(map[*dnsTLSExchange]struct{})
	}
	d.exchanges[exchange] = struct{}{}
	d.mu.Unlock()

	exchangeCtx, exchangeCancel := context.WithTimeout(forwardCtx, consts.DefaultDNSTimeout)
	defer exchangeCancel()
	request := msg.Copy()
	result := make(chan error, 1)
	workerStarted = true
	go func() {
		defer d.workers.Done()
		defer func() {
			d.mu.Lock()
			delete(d.exchanges, exchange)
			d.mu.Unlock()
		}()
		defer exchange.close()
		deadline, _ := exchangeCtx.Deadline()
		err := tlsConn.SetDeadline(deadline)
		if err == nil {
			stopContextClose := context.AfterFunc(exchangeCtx, exchange.close)
			err = tlsConn.HandshakeContext(exchangeCtx)
			if err == nil {
				err = netutils.ResolveStream(tlsConn, request)
			}
			stopContextClose()
		}
		result <- err
	}()

	select {
	case err = <-result:
		if err := dnsForwarderOperationError(ctx, d.state, exchangeCtx, err); err != nil {
			return err
		}
		*msg = *request
		return nil
	case <-exchangeCtx.Done():
		go exchange.close()
		return dnsForwarderOperationError(ctx, d.state, exchangeCtx, exchangeCtx.Err())
	}
}

func (d *tlsDNSForwarder) Close() error {
	if !d.state.close() {
		return nil
	}
	d.mu.Lock()
	exchanges := make([]*dnsTLSExchange, 0, len(d.exchanges))
	for exchange := range d.exchanges {
		exchanges = append(exchanges, exchange)
	}
	d.mu.Unlock()
	for _, exchange := range exchanges {
		go exchange.close()
	}
	done := make(chan struct{})
	go func() {
		d.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(consts.DefaultDialTimeout):
		return fmt.Errorf("DoT exchange shutdown timeout: %w", context.DeadlineExceeded)
	}
}
