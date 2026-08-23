/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
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
}

func (s *doqTestStream) Read(p []byte) (int, error)  { return s.response.Read(p) }
func (s *doqTestStream) Write(p []byte) (int, error) { return s.written.Write(p) }

type blockingCloseConn struct {
	net.Conn
	release <-chan struct{}
	once    sync.Once
}

type shortWriteConn struct{ net.Conn }

func (c *shortWriteConn) Write(p []byte) (int, error) { return len(p) - 1, nil }

type queuedDNSResponseConn struct {
	net.Conn
	response     []byte
	readReturned chan struct{}
	onRead       func()
}

func (c *queuedDNSResponseConn) Read(p []byte) (int, error) {
	n := copy(p, c.response)
	if c.onRead != nil {
		c.onRead()
	}
	close(c.readReturned)
	return n, nil
}

func (c *queuedDNSResponseConn) Write(p []byte) (int, error) {
	<-c.readReturned
	// Let ResolveUDP validate and queue the response before Write returns.
	time.Sleep(20 * time.Millisecond)
	return len(p), nil
}

func (c *queuedDNSResponseConn) Close() error { return nil }

func (c *blockingCloseConn) Close() error {
	<-c.release
	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
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
	releaseClose := make(chan struct{})
	defer close(releaseClose)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		conn := &blockingCloseConn{Conn: client, release: releaseClose}
		_, err := ResolveNetipContext(ctx, blockingDNSDialer{conn: conn}, netip.MustParseAddrPort("127.0.0.1:53"), "example.com", dnsmessage.TypeA, "tcp")
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
		query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
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
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("canceled UDP request did not close the connection")
	}
}

func TestResolveUDPCancellationDoesNotWaitForClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	releaseClose := make(chan struct{})
	defer close(releaseClose)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
		done <- ResolveUDP(ctx, &blockingCloseConn{Conn: client, release: releaseClose}, query)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled UDP request error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled UDP request waited for Close")
	}
}

func TestResolveUDPRejectsShortWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)

	err := ResolveUDP(context.Background(), &shortWriteConn{Conn: client}, query)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short UDP write error = %v, want io.ErrShortWrite", err)
	}
}

func TestResolveUDPPrefersQueuedResponseOverRetryTimer(t *testing.T) {
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn := &queuedDNSResponseConn{
		response:     payload,
		readReturned: make(chan struct{}),
	}

	if err := resolveUDP(context.Background(), conn, query, 0, time.Second); err != nil {
		t.Fatal(err)
	}
	if !query.Response || query.Id != 42 {
		t.Fatalf("unexpected UDP response: %+v", query)
	}
}

func TestResolveUDPDoesNotCommitAfterCancellation(t *testing.T) {
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn := &queuedDNSResponseConn{
		response:     payload,
		readReturned: make(chan struct{}),
		onRead:       cancel,
	}

	err = resolveUDP(ctx, conn, query, 0, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled UDP response error = %v, want context.Canceled", err)
	}
	if query.Response {
		t.Fatalf("canceled UDP response was committed: %+v", query)
	}
}

func TestResolveHttpAppliesAge(t *testing.T) {
	tests := []struct {
		name string
		age  string
		want uint32
	}{
		{name: "valid", age: "50", want: 10},
		{name: "combined", age: "50, 999", want: 10},
		{name: "invalid", age: "invalid", want: 60},
		{name: "overflow", age: "18446744073709551616", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
			query.Id = 42
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if got := req.URL.Query().Get("existing"); got != "value" {
					t.Fatalf("existing DoH query parameter = %q, want value", got)
				}
				wire, err := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
				if err != nil {
					return nil, err
				}
				var wireQuery dnsmessage.Msg
				if err := wireQuery.Unpack(wire); err != nil {
					return nil, err
				}
				if wireQuery.Id != 0 {
					t.Fatalf("DoH query ID = %d, want 0", wireQuery.Id)
				}
				response := new(dnsmessage.Msg)
				response.SetReply(&wireQuery)
				response.Answer = []dnsmessage.RR{&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.1").To4(),
				}}
				payload, err := response.Pack()
				if err != nil {
					return nil, err
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header: http.Header{
						"Content-Type": []string{"application/dns-message"},
						"Age":          []string{tt.age},
					},
					Body: io.NopCloser(bytes.NewReader(payload)),
				}, nil
			})}
			endpoint := &url.URL{Scheme: "https", Host: "dns.example", Path: "/dns-query", RawQuery: "existing=value"}
			originalURL := endpoint.String()
			if err := ResolveHttp(context.Background(), client, endpoint, query); err != nil {
				t.Fatal(err)
			}
			if got := endpoint.String(); got != originalURL {
				t.Fatalf("ResolveHttp mutated endpoint to %q, want %q", got, originalURL)
			}
			if query.Id != 42 {
				t.Fatalf("DoH response ID = %d, want 42", query.Id)
			}
			if got := query.Answer[0].Header().Ttl; got != tt.want {
				t.Fatalf("aged TTL = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestResolveHttpDoesNotCommitAfterCancellation(t *testing.T) {
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		wire, err := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
		if err != nil {
			return nil, err
		}
		var wireQuery dnsmessage.Msg
		if err := wireQuery.Unpack(wire); err != nil {
			return nil, err
		}
		response := new(dnsmessage.Msg)
		response.SetReply(&wireQuery)
		payload, err := response.Pack()
		if err != nil {
			return nil, err
		}
		cancel()
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/dns-message"}},
			Body:       io.NopCloser(bytes.NewReader(payload)),
		}, nil
	})}

	err := ResolveHttp(ctx, client, &url.URL{Scheme: "https", Host: "dns.example", Path: "/dns-query"}, query)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled DoH response error = %v, want context.Canceled", err)
	}
	if query.Response {
		t.Fatalf("canceled DoH response was committed: %+v", query)
	}
}

func TestResolveStreamFraming(t *testing.T) {
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42

	response := new(dnsmessage.Msg)
	response.SetReply(query)
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
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 42
	response := new(dnsmessage.Msg)
	response.SetReply(query)
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
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 7
	response := &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{
		Id:       7,
		Response: true,
		Rcode:    dnsmessage.RcodeRefused,
	}}
	if err := ValidateDnsResponseAllowEmptyQuestion(query, response, 7); err != nil {
		t.Fatal(err)
	}
	if len(response.Question) != 1 || response.Question[0] != query.Question[0] {
		t.Fatalf("question was not restored: %v", response.Question)
	}
}

func TestValidateDnsResponseRejectsHeaderOnlyUDPError(t *testing.T) {
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 7
	response := &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{
		Id:       7,
		Response: true,
		Rcode:    dnsmessage.RcodeRefused,
	}}
	if err := ValidateDnsResponse(query, response, 7); !errors.Is(err, ErrBadDnsResponse) {
		t.Fatalf("header-only UDP response error = %v", err)
	}
}

func TestValidateDnsResponseRejectsMismatch(t *testing.T) {
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
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
	query := new(dnsmessage.Msg).SetQuestion("example.com.", dnsmessage.TypeA)
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
