/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	policy "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dns "github.com/miekg/dns"
)

func exchangeHTTP(ctx context.Context, dialer netproxy.Dialer, target netip.AddrPort, upstream *policy.Upstream, msg *dns.Msg) error {
	tlsConfig := &tls.Config{ServerName: upstream.Hostname}
	var rt http.RoundTripper
	if upstream.Scheme == policy.UpstreamScheme_H3 {
		transport := &http3.Transport{
			TLSClientConfig: tlsConfig,
			Dial: func(dialCtx context.Context, _ string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				// This invocation owns the socket; a failed/retried HTTP/3 dial
				// releases it when its QUIC connection ends.
				return dialQUIC(dialCtx, dialer, target, config, quicConfig)
			},
		}
		defer transport.Close()
		rt = transport
	} else {
		transport := &http.Transport{
			TLSClientConfig:   tlsConfig,
			ForceAttemptHTTP2: true,
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				// net/http may detach a dial from the request. The whole transport
				// belongs to this exchange, so its dial uses the exchange context.
				return dialer.DialContext(ctx, "tcp", target.String())
			},
		}
		defer transport.CloseIdleConnections()
		rt = transport
	}
	client := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("DNS endpoint must not redirect: %s", upstream)
	}}
	return ResolveHttp(ctx, client, &url.URL{
		Scheme: "https", Host: net.JoinHostPort(upstream.Hostname, fmt.Sprint(upstream.Port)),
		Path: upstream.Path, RawPath: upstream.RawPath, RawQuery: upstream.RawQuery,
	}, msg)
}
