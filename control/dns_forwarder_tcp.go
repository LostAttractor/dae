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
	dialing      chan struct{}
	retiring     *DnsManager
	closeErr     error
}

func (d *tcpDNSForwarder) Close() error {
	if !d.state.close() {
		return nil
	}
	d.mu.Lock()
	manager, retiring, dialing, priorErr := d.dnsManager, d.retiring, d.dialing, d.closeErr
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
	if dialing != nil {
		select {
		case <-dialing:
		case <-ctx.Done():
			err = errors.Join(err, ctx.Err())
		}
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
	ctx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d.mu.Lock()
		if d.state.isClosed() {
			d.mu.Unlock()
			return nil, net.ErrClosed
		}
		if d.dialing != nil {
			done := d.dialing
			d.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if d.dnsManager != nil && !d.dnsManager.IsClosed() {
			manager := d.dnsManager
			d.mu.Unlock()
			return manager, nil
		}
		if (d.dnsManager != nil && !d.dnsManager.canReplace()) || !d.clearRetiringLocked() {
			d.mu.Unlock()
			return nil, net.ErrClosed
		}
		previous := d.dnsManager
		done := make(chan struct{})
		d.dialing = done
		d.mu.Unlock()

		// One caller owns the dial; waiters can cancel without waiting for it.
		dialCtx, cancelDial := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		conn, err := d.dialArgument.dialerForConnection().DialContext(dialCtx, "tcp", d.dialArgument.Target.String())
		err = dnsForwarderOperationError(ctx, d.state, dialCtx, err)
		cancelDial()

		d.mu.Lock()
		if d.state.isClosed() {
			err = net.ErrClosed
		}
		var manager *DnsManager
		if err == nil {
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
		} else {
			closeInBackground(conn)
		}
		d.dialing = nil
		close(done)
		d.mu.Unlock()
		return manager, err
	}
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
