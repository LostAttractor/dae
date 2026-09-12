// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"

	policy "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	dns "github.com/miekg/dns"
)

// Exchange owns one query's transport. The caller supplies the selected address
// and a request-bound dialer; nothing is pooled across exchanges or clients.
// A failed/canceled exchange never modifies query or publishes a partial reply.
func Exchange(ctx context.Context, upstream *policy.Upstream, dialer netproxy.Dialer, target netip.AddrPort, protocol string, query *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scheme := upstream.Scheme
	if scheme == policy.UpstreamScheme_TCP_UDP {
		scheme = policy.UpstreamScheme(protocol)
	}
	if err := validateDNSForwardQuery(query, string(scheme), scheme != policy.UpstreamScheme_HTTPS && scheme != policy.UpstreamScheme_H3); err != nil {
		return nil, err
	}
	response := query.Copy()
	var err error
	switch scheme {
	case policy.UpstreamScheme_UDP:
		err = exchangeUDP(ctx, dialer, target, response)
	case policy.UpstreamScheme_TCP, policy.UpstreamScheme_TLS:
		err = exchangeTCP(ctx, dialer, target, upstream, response)
	case policy.UpstreamScheme_HTTPS, policy.UpstreamScheme_H3:
		err = exchangeHTTP(ctx, dialer, target, upstream, response)
	case policy.UpstreamScheme_QUIC:
		err = exchangeQUIC(ctx, dialer, target, upstream, response)
	default:
		err = fmt.Errorf("unsupported DNS transport %q", scheme)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	response.Id = query.Id
	return response, nil
}

// The I/O worker owns the response and closes its socket. On cancellation,
// interrupt I/O without making the caller wait for an outbound's blocking Close.
func exchangeIO(ctx context.Context, conn io.Closer, exchange func() error) error {
	closeConn := sync.OnceFunc(func() { _ = conn.Close() })
	done := make(chan error, 1)
	go func() {
		defer closeConn()
		done <- exchange()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		go closeConn()
		return ctx.Err()
	}
}

func hasDnsTransactionSignature(msg *dns.Msg) bool {
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeTSIG || rr.Header().Rrtype == dns.TypeSIG {
			return true
		}
	}
	return false
}

func validateDNSForwardQuery(msg *dns.Msg, transport string, rejectZoneTransfer bool) error {
	for _, question := range msg.Question {
		if rejectZoneTransfer && (question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR) {
			return fmt.Errorf("%s zone transfers are not supported", transport)
		}
	}
	if hasDnsTransactionSignature(msg) {
		return fmt.Errorf("%s transport does not support transaction signatures", transport)
	}
	return nil
}
