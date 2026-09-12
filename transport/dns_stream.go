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
	"fmt"
	"io"
	"net/netip"

	policy "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
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
	for attempt := 0; attempt < 2; attempt++ {
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
			return exchangeStream(conn, msg)
		})
		// Only plain TCP query exchanges retry an interrupted connection. No
		// retransmission occurs on a live stream, and DoT retains one attempt.
		if err == nil || ctx.Err() != nil || upstream.Scheme == policy.UpstreamScheme_TLS || msg.Opcode != dns.OpcodeQuery {
			return err
		}
	}
	return err
}

func exchangeStream(stream io.ReadWriter, msg *dns.Msg) error {
	wire, err := msg.Pack()
	if err != nil {
		return err
	}
	if err := netutils.CheckDnsMessageSize(len(wire)); err != nil {
		return err
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	if n, err := stream.Write(frame); err != nil {
		return fmt.Errorf("write DNS query: %w", err)
	} else if n != len(frame) {
		return io.ErrShortWrite
	}
	for {
		var prefix [2]byte
		if _, err := io.ReadFull(stream, prefix[:]); err != nil {
			return fmt.Errorf("read DNS response length: %w", err)
		}
		wire := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(stream, wire); err != nil {
			return fmt.Errorf("read DNS response: %w", err)
		}
		response := new(dns.Msg)
		if netutils.UnpackDnsMessage(wire, response) != nil || netutils.ValidateDnsResponseAllowEmptyQuestion(msg, response, msg.Id) != nil {
			continue
		}
		*msg = *response
		return nil
	}
}
