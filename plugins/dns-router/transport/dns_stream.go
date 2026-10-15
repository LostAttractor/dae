/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net/netip"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	policy "github.com/daeuniverse/dae/plugins/dns-router/policy"
	dns "github.com/miekg/dns"
)

func exchangeUDP(ctx context.Context, dialer netproxy.Dialer, target netip.AddrPort, msg *dns.Msg) error {
	conn, err := dialer.DialContext(ctx, "udp", target.String())
	if err != nil {
		return err
	}
	return exchangeIO(ctx, conn, func() error {
		var id [2]byte
		rand.Read(id[:])
		msg.Id = binary.BigEndian.Uint16(id[:])
		return netutils.ResolveUDP(ctx, conn, msg)
	})
}

func exchangeTCP(ctx context.Context, dialer netproxy.Dialer, target netip.AddrPort, upstream *policy.Upstream, msg *dns.Msg) error {
	var err error
	for range 2 {
		conn, dialErr := dialer.DialContext(ctx, "tcp", target.String())
		if dialErr != nil {
			return dialErr
		}
		err = exchangeIO(ctx, conn, func() error {
			if upstream.Scheme == policy.UpstreamScheme_TLS {
				secured := tls.Client(conn, &tls.Config{ServerName: upstream.Hostname})
				if err := secured.HandshakeContext(ctx); err != nil {
					return err
				}
				return netutils.ResolveStream(secured, msg)
			}
			return netutils.ResolveStreamFiltered(conn, msg)
		})
		// Only plain TCP query exchanges retry an interrupted connection. No
		// retransmission occurs on a live stream, and DoT retains one attempt.
		if err == nil || ctx.Err() != nil || upstream.Scheme == policy.UpstreamScheme_TLS || msg.Opcode != dns.OpcodeQuery {
			return err
		}
	}
	return err
}
