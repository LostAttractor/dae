/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

type blockingDNSDialer struct{ conn net.Conn }

func (d blockingDNSDialer) Alive() bool { return true }
func (d blockingDNSDialer) Connect() error {
	return nil
}
func (d blockingDNSDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
func (d blockingDNSDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestResolveNetipContextCancellationClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := ResolveNetipContext(ctx, blockingDNSDialer{conn: client}, netip.MustParseAddrPort("127.0.0.1:53"), "example.com", dnsmessage.TypeA, "tcp")
		done <- err
	}()
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled DNS request unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled DNS request did not unblock")
	}
}
