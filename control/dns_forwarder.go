/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type DnsForwarder interface {
	// ForwardDNS must return after ctx is canceled or Close interrupts it.
	ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error
	io.Closer
}

func hasDnsTransactionSignature(msg *dnsmessage.Msg) bool {
	for _, rr := range msg.Extra {
		if rr != nil && (rr.Header().Rrtype == dnsmessage.TypeTSIG || rr.Header().Rrtype == dnsmessage.TypeSIG) {
			return true
		}
	}
	return false
}

func validateDNSForwardQuery(msg *dnsmessage.Msg, transport string, rejectZoneTransfer bool) error {
	for _, question := range msg.Question {
		if rejectZoneTransfer && (question.Qtype == dnsmessage.TypeAXFR || question.Qtype == dnsmessage.TypeIXFR) {
			return fmt.Errorf("%s zone transfers are not supported", transport)
		}
	}
	if hasDnsTransactionSignature(msg) {
		return fmt.Errorf("%s forwarder does not support transaction signatures", transport)
	}
	return nil
}

func dnsForwarderOperationError(callerCtx context.Context, state *dnsForwarderState, operationCtx context.Context, operationErr error) error {
	if err := callerCtx.Err(); err != nil {
		return err
	}
	if state.isClosed() {
		return net.ErrClosed
	}
	if err := state.ctx.Err(); err != nil {
		return err
	}
	if err := operationCtx.Err(); err != nil {
		return err
	}
	return operationErr
}

type dnsForwarderState struct {
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
}

func newDNSForwarderState(parent context.Context) *dnsForwarderState {
	ctx, cancel := context.WithCancel(parent)
	return &dnsForwarderState{ctx: ctx, cancel: cancel}
}

func (s *dnsForwarderState) isClosed() bool {
	return s.closed.Load()
}

func (s *dnsForwarderState) close() bool {
	if !s.closed.CompareAndSwap(false, true) {
		return false
	}
	s.cancel()
	return true
}

func (s *dnsForwarderState) deriveContext(ctx context.Context) (context.Context, context.CancelFunc) {
	derived, cancel := context.WithCancel(ctx)
	if s.ctx.Err() != nil {
		cancel()
		return derived, cancel
	}
	stop := context.AfterFunc(s.ctx, cancel)
	return derived, func() {
		stop()
		cancel()
	}
}

// All forwarders enter through this factory with a live lifecycle state.
// Concrete implementations do not support zero-value or nil-context use.
func newDnsForwarder(parent context.Context, upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	state := newDNSForwarderState(parent)
	var forwarder DnsForwarder
	switch dialArgument.networkType.L4Proto {
	case consts.L4ProtoStr_TCP:
		switch upstream.Scheme {
		case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
			forwarder = &tcpDNSForwarder{Upstream: *upstream, dialArgument: dialArgument, state: state}
		case dns.UpstreamScheme_TLS:
			forwarder = &tlsDNSForwarder{Upstream: *upstream, dialArgument: dialArgument, state: state}
		case dns.UpstreamScheme_HTTPS:
			forwarder = &httpDNSForwarder{Upstream: *upstream, dialArgument: dialArgument, state: state}
		}
	case consts.L4ProtoStr_UDP:
		switch upstream.Scheme {
		case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
			forwarder = &udpDNSForwarder{
				Upstream: *upstream, dialArgument: dialArgument, state: state,
				slots: make(chan struct{}, maxConcurrentDnsUDPExchanges), closeDone: make(chan struct{}),
			}
		case dns.UpstreamScheme_QUIC:
			forwarder = &quicDNSForwarder{Upstream: *upstream, dialArgument: dialArgument, state: state}
		case dns.UpstreamScheme_H3:
			forwarder = &httpDNSForwarder{Upstream: *upstream, dialArgument: dialArgument, http3: true, state: state}
		}
	}
	if forwarder == nil {
		state.close()
		return nil, fmt.Errorf("unsupported DNS upstream %s over %s", upstream.Scheme, dialArgument.networkType.L4Proto)
	}
	return forwarder, nil
}
