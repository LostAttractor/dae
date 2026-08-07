/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

type blockingDNSDialer struct{ conn net.Conn }

type doqTestStream struct {
	response *bytes.Reader
	written  bytes.Buffer
	closed   bool
}

func (s *doqTestStream) Read(p []byte) (int, error)  { return s.response.Read(p) }
func (s *doqTestStream) Write(p []byte) (int, error) { return s.written.Write(p) }
func (s *doqTestStream) Close() error {
	s.closed = true
	return nil
}

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

func TestResolveStreamDoQFraming(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42

	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Id = 0
	response.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "example.com.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("192.0.2.1").To4(),
	}}
	responsePayload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	responseFrame := make([]byte, 2+len(responsePayload))
	binary.BigEndian.PutUint16(responseFrame[:2], uint16(len(responsePayload)))
	copy(responseFrame[2:], responsePayload)

	stream := &doqTestStream{response: bytes.NewReader(responseFrame)}
	if err := ResolveStream(stream, query, true); err != nil {
		t.Fatal(err)
	}
	if !stream.closed {
		t.Fatal("DoQ query did not close its send side")
	}

	written := stream.written.Bytes()
	if len(written) < 2 {
		t.Fatalf("DoQ query is missing its length prefix: %x", written)
	}
	if got, want := int(binary.BigEndian.Uint16(written[:2])), len(written)-2; got != want {
		t.Fatalf("DoQ query length prefix = %d, want %d", got, want)
	}
	var wireQuery dnsmessage.Msg
	if err := wireQuery.Unpack(written[2:]); err != nil {
		t.Fatalf("unpack framed DoQ query: %v", err)
	}
	if wireQuery.Id != 0 {
		t.Fatalf("DoQ query ID = %d, want 0", wireQuery.Id)
	}
	if !query.Response || query.Id != 0 || len(query.Answer) != 1 {
		t.Fatalf("unexpected DoQ response: %+v", query)
	}
}

func TestResolveStreamDoQRejectsUnframedResponse(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Id = 0
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}

	stream := &doqTestStream{response: bytes.NewReader(payload)}
	err = ResolveStream(stream, query, true)
	if err == nil {
		t.Fatal("unframed DoQ response unexpectedly succeeded")
	}
}
