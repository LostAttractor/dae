/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/quic-go"
	dnsmessage "github.com/miekg/dns"
)

type doqTimeoutError struct{}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func (doqTimeoutError) Error() string   { return "timeout" }
func (doqTimeoutError) Timeout() bool   { return true }
func (doqTimeoutError) Temporary() bool { return true }

type doqTestStream struct {
	response     *bytes.Reader
	written      bytes.Buffer
	withholdFin  bool
	writeLimit   int
	closeCalls   int
	cancelReads  int
	cancelWrites int
}

func (s *doqTestStream) Read(p []byte) (int, error) {
	if s.response.Len() != 0 {
		return s.response.Read(p)
	}
	if s.withholdFin {
		return 0, doqTimeoutError{}
	}
	return 0, io.EOF
}

func (s *doqTestStream) Write(p []byte) (int, error) {
	if s.writeLimit > 0 && len(p) > s.writeLimit {
		_, _ = s.written.Write(p[:s.writeLimit])
		return s.writeLimit, nil
	}
	return s.written.Write(p)
}

func (s *doqTestStream) Close() error {
	s.closeCalls++
	return nil
}

func (s *doqTestStream) CancelRead(quic.StreamErrorCode)  { s.cancelReads++ }
func (s *doqTestStream) CancelWrite(quic.StreamErrorCode) { s.cancelWrites++ }
func (s *doqTestStream) Context() context.Context         { return context.Background() }

func framedDoqResponse(t *testing.T, query *dnsmessage.Msg) []byte {
	t.Helper()
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Id = 0
	response.Answer = []dnsmessage.RR{testARecord(query.Question[0].Name, "192.0.2.1")}
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	return frame
}

func framedDoqKeepaliveResponse(t *testing.T, query *dnsmessage.Msg) []byte {
	t.Helper()
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Id = 0
	response.SetEdns0(1232, false)
	response.IsEdns0().Option = append(response.IsEdns0().Option, &dnsmessage.EDNS0_TCP_KEEPALIVE{
		Code: dnsmessage.EDNS0TCPKEEPALIVE,
	})
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	return frame
}

func TestResolveDoQCommitsAfterFin(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	stream := &doqTestStream{response: bytes.NewReader(framedDoqResponse(t, query))}
	if err := resolveDoQ(stream, query); err != nil {
		t.Fatal(err)
	}
	if stream.closeCalls != 1 || stream.cancelWrites != 0 {
		t.Fatalf("send-side cleanup: Close=%d CancelWrite=%d", stream.closeCalls, stream.cancelWrites)
	}
	written := stream.written.Bytes()
	if (len(written)-2)%128 != 0 {
		t.Fatalf("padded DoQ message length = %d, want a multiple of 128", len(written)-2)
	}
	if got, want := int(binary.BigEndian.Uint16(written[:2])), len(written)-2; got != want {
		t.Fatalf("query frame length = %d, want %d", got, want)
	}
	var wireQuery dnsmessage.Msg
	if err := wireQuery.Unpack(written[2:]); err != nil {
		t.Fatal(err)
	}
	if wireQuery.Id != 0 || !query.Response || len(query.Answer) != 1 {
		t.Fatalf("unexpected DoQ exchange: wire=%+v response=%+v", wireQuery, query)
	}
}

func TestResolveDoQMissingFinLeavesQueryUntouched(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	stream := &doqTestStream{
		response:    bytes.NewReader(framedDoqResponse(t, query)),
		withholdFin: true,
	}
	err := resolveDoQ(stream, query)
	var protocolErr *doqProtocolErrorCause
	if !errors.As(err, &protocolErr) {
		t.Fatalf("missing FIN error = %v, want protocol error", err)
	}
	if query.Response || query.Id != 42 || len(query.Answer) != 0 {
		t.Fatalf("failed DoQ exchange mutated query: %+v", query)
	}
}

func TestResolveDoQPartialWriteCancelsWrite(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	stream := &doqTestStream{
		response:   bytes.NewReader(nil),
		writeLimit: 3,
	}
	err := resolveDoQ(stream, query)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial write error = %v, want io.ErrShortWrite", err)
	}
	if stream.cancelWrites != 1 || stream.closeCalls != 0 {
		t.Fatalf("partial write cleanup: CancelWrite=%d Close=%d", stream.cancelWrites, stream.closeCalls)
	}
}

func TestResolveDoQRejectsTcpKeepalive(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	stream := &doqTestStream{response: bytes.NewReader(framedDoqKeepaliveResponse(t, query))}
	err := resolveDoQ(stream, query)
	var protocolErr *doqProtocolErrorCause
	if !errors.As(err, &protocolErr) {
		t.Fatalf("TCP keepalive error = %v, want protocol error", err)
	}
	if query.Response || query.Id != 42 || len(query.Answer) != 0 {
		t.Fatalf("forbidden DoQ response mutated query: %+v", query)
	}
}

func TestDoQRejectsTcpKeepaliveQueryBeforeDial(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	query.SetEdns0(1232, false)
	query.IsEdns0().Option = append(query.IsEdns0().Option, &dnsmessage.EDNS0_TCP_KEEPALIVE{
		Code: dnsmessage.EDNS0TCPKEEPALIVE,
	})
	if err := (&DoQ{}).ForwardDNS(context.Background(), query); err == nil {
		t.Fatal("DoQ query with TCP keepalive unexpectedly reached the dial path")
	}
}

func TestDoQRejectsMultipleOptRecordsBeforeDial(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	query.Extra = append(query.Extra,
		&dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT}},
		&dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT}},
	)
	if err := (&DoQ{}).ForwardDNS(context.Background(), query); err == nil {
		t.Fatal("DoQ query with multiple OPT records unexpectedly reached the dial path")
	}
}

func TestDoQRejectsInvalidOptBeforeDial(t *testing.T) {
	tests := []struct {
		name string
		opt  *dnsmessage.OPT
	}{
		{
			name: "non-root owner",
			opt:  &dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeOPT}},
		},
		{
			name: "multiple padding",
			opt: &dnsmessage.OPT{
				Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT},
				Option: []dnsmessage.EDNS0{
					&dnsmessage.EDNS0_PADDING{},
					&dnsmessage.EDNS0_PADDING{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := testQuery("example.com.", dnsmessage.TypeA, 42)
			query.Extra = append(query.Extra, tt.opt)
			if err := (&DoQ{}).ForwardDNS(context.Background(), query); err == nil {
				t.Fatal("invalid DoQ OPT unexpectedly reached the dial path")
			}
		})
	}
}

func TestDoQRejectsOptOutsideAdditional(t *testing.T) {
	msg := testQuery("example.com.", dnsmessage.TypeA, 42)
	msg.Answer = append(msg.Answer, &dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT}})
	if err := validateDoqOptions(msg); err == nil {
		t.Fatal("OPT outside the additional section was accepted")
	}
}

func TestResolveDoQDoesNotTreatSignatureAsProtocolError(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	response := new(dnsmessage.Msg)
	response.SetReply(query)
	response.Id = 0
	response.Extra = append(response.Extra, &dnsmessage.TSIG{
		Hdr:       dnsmessage.RR_Header{Name: "key.example.", Rrtype: dnsmessage.TypeTSIG, Class: dnsmessage.ClassANY},
		Algorithm: dnsmessage.HmacSHA256,
		Fudge:     300,
	})
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	stream := &doqTestStream{response: bytes.NewReader(frame)}
	err = resolveDoQ(stream, query)
	if err == nil {
		t.Fatal("signed DoQ response unexpectedly succeeded")
	}
	var protocolErr *doqProtocolErrorCause
	if errors.As(err, &protocolErr) {
		t.Fatalf("unsupported signature was treated as a DoQ protocol error: %v", err)
	}
}

func TestResolveDoQRejectsTrailingData(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	response := append(framedDoqResponse(t, query), 0)
	stream := &doqTestStream{response: bytes.NewReader(response)}
	err := resolveDoQ(stream, query)
	var protocolErr *doqProtocolErrorCause
	if !errors.As(err, &protocolErr) {
		t.Fatalf("trailing DoQ data error = %v, want protocol error", err)
	}
	if query.Response {
		t.Fatal("response with trailing data mutated the query")
	}
}

func TestPackDoqQueryUsesAvailableNearLimitPadding(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 42)
	null := &dnsmessage.NULL{Hdr: dnsmessage.RR_Header{
		Name:     ".",
		Rrtype:   dnsmessage.TypeNULL,
		Class:    dnsmessage.ClassINET,
		Ttl:      0,
		Rdlength: 0,
	}}
	query.Extra = append(query.Extra, null)
	base, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = 65500
	null.Data = strings.Repeat("x", targetSize-len(base))
	if payload, err := query.Pack(); err != nil || len(payload) != targetSize {
		t.Fatalf("near-limit query size = %d, err = %v", len(payload), err)
	}

	packedQuery, frame, err := packDoqQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 65535+2 {
		t.Fatalf("near-limit DoQ frame size = %d, want %d", len(frame), 65535+2)
	}
	opt := packedQuery.IsEdns0()
	if opt == nil || len(opt.Option) != 1 {
		t.Fatal("near-limit query did not use the remaining space for padding")
	}
	padding, ok := opt.Option[0].(*dnsmessage.EDNS0_PADDING)
	if !ok || len(padding.Padding) != 20 {
		t.Fatalf("near-limit padding = %#v, want 20 bytes", opt.Option[0])
	}
}

func TestDoHUsesHostnameAsAuthority(t *testing.T) {
	forwarder := &DoH{
		Upstream: dns.Upstream{
			Scheme:   dns.UpstreamScheme_HTTPS,
			Hostname: "dns.example",
			Port:     443,
			Path:     "/dns-query",
		},
	}
	forwarder.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "dns.example:443" || req.Host != "dns.example:443" {
			t.Fatalf("DoH authority: URL=%q Host=%q", req.URL.Host, req.Host)
		}
		wire, err := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
		if err != nil {
			t.Fatal(err)
		}
		var query dnsmessage.Msg
		if err := query.Unpack(wire); err != nil {
			t.Fatal(err)
		}
		response := new(dnsmessage.Msg)
		response.SetReply(&query)
		payload, err := response.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/dns-message"}},
			Body:       io.NopCloser(bytes.NewReader(payload)),
		}, nil
	})}
	msg := testQuery("example.com.", dnsmessage.TypeA, 42)
	if err := forwarder.ForwardDNS(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
}
