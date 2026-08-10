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
func TestValidateDnsResponseRestoresHeaderOnlyErrorQuestion(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 7
	response := &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{
		Id:       7,
		Response: true,
		Rcode:    dnsmessage.RcodeRefused,
	}}
	if err := ValidateDnsResponse(query, response, 7); err != nil {
		t.Fatal(err)
	}
	if len(response.Question) != 1 || response.Question[0] != query.Question[0] {
		t.Fatalf("question was not restored: %v", response.Question)
	}
}

func TestValidateDnsResponseRejectsMismatch(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 7
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Question[0].Name = "other.example."
	if err := ValidateDnsResponse(query, response, 7); !errors.Is(err, ErrBadDnsResponse) {
		t.Fatalf("mismatched response error = %v", err)
	}
}

func TestCheckDnsMessageSize(t *testing.T) {
	if err := CheckDnsMessageSize(65535); err != nil {
		t.Fatal(err)
	}
	if err := CheckDnsMessageSize(65536); err == nil {
		t.Fatal("oversized DNS message unexpectedly accepted")
	}
}
