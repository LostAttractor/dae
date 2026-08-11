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
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

type blockingDNSDialer struct{ conn net.Conn }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

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
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled DNS request error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled DNS request did not unblock")
	}
}

func TestResolveUDPCancellationClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		query := new(dnsmessage.Msg)
		query.SetQuestion("example.com.", dnsmessage.TypeA)
		done <- ResolveUDP(ctx, client, query)
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled UDP request error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled UDP request did not unblock")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("canceled UDP request left the connection open")
	}
}

func TestResolveHttpAppliesAge(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := new(dnsmessage.Msg)
		response.SetReply(query)
		response.Id = 0
		response.Answer = []dnsmessage.RR{
			&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1").To4()},
			&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 10}, A: net.ParseIP("192.0.2.2").To4()},
		}
		payload, err := response.Pack()
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header: http.Header{
				"Content-Type": []string{"application/dns-message"},
				"Age":          []string{"50"},
			},
			Body: io.NopCloser(bytes.NewReader(payload)),
		}, nil
	})}
	if err := ResolveHttp(context.Background(), client, &url.URL{Scheme: "https", Host: "dns.example", Path: "/dns-query"}, query); err != nil {
		t.Fatal(err)
	}
	if got := query.Answer[0].Header().Ttl; got != 10 {
		t.Fatalf("aged TTL = %d, want 10", got)
	}
	if got := query.Answer[1].Header().Ttl; got != 0 {
		t.Fatalf("saturated aged TTL = %d, want 0", got)
	}
}

func TestResolveStreamFraming(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42

	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Id = query.Id
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
	if err := ResolveStream(stream, query); err != nil {
		t.Fatal(err)
	}

	written := stream.written.Bytes()
	if len(written) < 2 {
		t.Fatalf("stream query is missing its length prefix: %x", written)
	}
	if got, want := int(binary.BigEndian.Uint16(written[:2])), len(written)-2; got != want {
		t.Fatalf("stream query length prefix = %d, want %d", got, want)
	}
	var wireQuery dnsmessage.Msg
	if err := wireQuery.Unpack(written[2:]); err != nil {
		t.Fatalf("unpack framed stream query: %v", err)
	}
	if wireQuery.Id != 42 {
		t.Fatalf("stream query ID = %d, want 42", wireQuery.Id)
	}
	if !query.Response || query.Id != 42 || len(query.Answer) != 1 {
		t.Fatalf("unexpected stream response: %+v", query)
	}
}

func TestResolveStreamRejectsUnframedResponse(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Id = query.Id
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}

	stream := &doqTestStream{response: bytes.NewReader(payload)}
	err = ResolveStream(stream, query)
	if err == nil {
		t.Fatal("unframed stream response unexpectedly succeeded")
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

func TestUnpackDnsMessageWireBoundaries(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		payload []byte
		wantErr bool
	}{
		{name: "valid", payload: payload},
		{name: "trailing byte", payload: append(append([]byte(nil), payload...), 0), wantErr: true},
		{name: "truncated question", payload: payload[:len(payload)-1], wantErr: true},
		{name: "forward pointer", payload: append(append([]byte(nil), payload[:12]...), 0xc0, 0x0e, 0, 1, 0, 1), wantErr: true},
		{name: "reserved label type", payload: append(append([]byte(nil), payload[:12]...), 0x40, 0, 1, 0, 1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg dnsmessage.Msg
			err := UnpackDnsMessage(tt.payload, &msg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnpackDnsMessage() error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
