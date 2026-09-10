/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

// The TCP forwarder reuses a connection. UDP uses a separate socket per
// exchange so concurrent queries cannot share a source port.
type tcpDNSForwarder struct {
	dns.Upstream
	dialArgument dialArgument
	state        *dnsForwarderState
	mu           sync.Mutex
	dnsManager   *DnsManager
	retiring     *DnsManager
	closeErr     error
}

func (d *tcpDNSForwarder) Close() error {
	if !d.state.close() {
		return nil
	}
	d.mu.Lock()
	manager, retiring, priorErr := d.dnsManager, d.retiring, d.closeErr
	d.dnsManager = nil
	d.retiring = nil
	d.closeErr = nil
	d.mu.Unlock()
	err := priorErr
	if manager != nil {
		manager.startClose()
	}
	if retiring != nil && retiring != manager {
		retiring.startClose()
	}
	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer cancel()
	if manager != nil {
		err = errors.Join(err, manager.waitClosed(ctx))
	}
	if retiring != nil && retiring != manager {
		err = errors.Join(err, retiring.waitClosed(ctx))
	}
	return err
}

func (d *tcpDNSForwarder) clearRetiringLocked() bool {
	if d.retiring == nil {
		return true
	}
	if !d.retiring.closeComplete() {
		return false
	}
	d.closeErr = errors.Join(d.closeErr, d.retiring.closeErr)
	d.retiring = nil
	return true
}

func (d *tcpDNSForwarder) allowIdleClose(manager *DnsManager) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.isClosed() || d.dnsManager != manager {
		return true
	}
	return d.clearRetiringLocked()
}

func (d *tcpDNSForwarder) getManager(ctx context.Context) (*DnsManager, error) {
	if d.state.isClosed() {
		return nil, net.ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.isClosed() {
		return nil, net.ErrClosed
	}
	if d.dnsManager == nil || d.dnsManager.IsClosed() {
		if d.dnsManager != nil && !d.dnsManager.canReplace() {
			return nil, net.ErrClosed
		}
		if !d.clearRetiringLocked() {
			return nil, net.ErrClosed
		}
		previous := d.dnsManager
		dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		defer cancel()
		conn, err := d.dialArgument.dialerForConnection().DialContext(dialCtx, "tcp", d.dialArgument.Target.String())
		if err != nil {
			return nil, err
		}
		if d.state.isClosed() {
			closeInBackground(conn)
			return nil, net.ErrClosed
		}
		var manager *DnsManager
		manager = newDnsManagerWithIdlePolicy(
			conn,
			consts.DefaultDNSTimeout,
			2*consts.DefaultDNSTimeout,
			func() bool { return d.allowIdleClose(manager) },
		)
		if previous != nil {
			if previous.closeComplete() {
				d.closeErr = errors.Join(d.closeErr, previous.closeErr)
			} else {
				d.retiring = previous
			}
		}
		d.dnsManager = manager
	}
	return d.dnsManager, nil
}

func (d *tcpDNSForwarder) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if err := validateDNSForwardQuery(msg, "TCP", true); err != nil {
		return err
	}
	parentCtx := ctx
	ctx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	ctx, cancelTimeout := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancelTimeout()
	var lastErr error
	for attempts := 0; attempts < 2; attempts++ {
		manager, err := d.getManager(ctx)
		if err != nil {
			if parentCtx.Err() != nil {
				return parentCtx.Err()
			}
			if d.state.isClosed() {
				return net.ErrClosed
			}
			return err
		}
		response := msg.Copy()
		err = manager.ResolveContext(ctx, response)
		lastErr = err
		if !shouldRetryDnsManager(err, msg) || ctx.Err() != nil {
			if err != nil && parentCtx.Err() != nil {
				return parentCtx.Err()
			}
			if err != nil && d.state.isClosed() {
				return net.ErrClosed
			}
			if err == nil {
				if err := ctx.Err(); err != nil {
					return err
				}
				*msg = *response
			}
			return err
		}
	}
	return lastErr
}

func shouldRetryDnsManager(err error, msg *dnsmessage.Msg) bool {
	if errors.Is(err, errDnsManagerUnavailable) {
		return true
	}
	return msg.Opcode == dnsmessage.OpcodeQuery && errors.Is(err, errDnsExchangeInterrupted)
}
