// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	dns "github.com/miekg/dns"
)

type httpRoundTripFunc func(*http.Request) (*http.Response, error)

func (f httpRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestResolveHTTPAgeAndCancellation(t *testing.T) {
	for _, test := range []struct {
		age    string
		want   uint32
		cancel bool
	}{{"50", 10, false}, {"50, 999", 10, false}, {"invalid", 60, false}, {"18446744073709551616", 0, false}, {"0", 60, true}} {
		ctx, cancel := context.WithCancel(t.Context())
		query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		query.Id = 42
		client := &http.Client{Transport: httpRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Query().Get("existing") != "value" {
				t.Fatal("endpoint query lost")
			}
			wire, err := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
			if err != nil {
				return nil, err
			}
			m := new(dns.Msg)
			if err := m.Unpack(wire); err != nil {
				return nil, err
			}
			if m.Id != 0 {
				t.Fatal("DoH ID not zero")
			}
			m.Response = true
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
			payload, _ := m.Pack()
			if test.cancel {
				cancel()
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/dns-message"}, "Age": {test.age}}, Body: io.NopCloser(bytes.NewReader(payload))}, nil
		})}
		endpoint := &url.URL{Scheme: "https", Host: "dns.example", Path: "/dns-query", RawQuery: "existing=value"}
		err := ResolveHttp(ctx, client, endpoint, query)
		cancel()
		if test.cancel {
			if !errors.Is(err, context.Canceled) || query.Response {
				t.Fatal("canceled response committed")
			}
			continue
		}
		if err != nil || query.Id != 42 || query.Answer[0].Header().Ttl != test.want || endpoint.RawQuery != "existing=value" {
			t.Fatalf("DoH age/identity: %s %v", query, err)
		}
	}
}

func TestResolveHTTPAgesEffectiveTTL(t *testing.T) {
	for _, test := range []struct {
		name         string
		rcode        int
		ttl, minimum uint32
		age          uint64
		want         uint32
	}{
		{"high bit", dns.RcodeSuccess, 1 << 31, 0, 1, 0},
		{"maximum TTL", dns.RcodeSuccess, 1<<32 - 1, 0, 1 << 31, 0},
		{"negative partly aged", dns.RcodeNameError, 60, 5, 3, 2},
		{"negative expired", dns.RcodeNameError, 60, 5, 10, 0},
		{"NODATA partly aged", dns.RcodeSuccess, 60, 5, 3, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			client := &http.Client{Transport: httpRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				m := new(dns.Msg).SetReply(query)
				m.Id, m.Rcode = 0, test.rcode
				if test.minimum != 0 {
					m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: test.ttl}, Ns: "ns.example.com.", Mbox: "hostmaster.example.com.", Minttl: test.minimum}}
				} else {
					m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: test.ttl}, A: net.ParseIP("192.0.2.1")}}
				}
				m.SetEdns0(1232, true)
				wire, err := m.Pack()
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/dns-message"}, "Age": {strconv.FormatUint(test.age, 10)}}, Body: io.NopCloser(bytes.NewReader(wire))}, err
			})}
			if err := ResolveHttp(t.Context(), client, &url.URL{Scheme: "https", Host: "dns.example", Path: "/dns-query"}, query); err != nil {
				t.Fatal(err)
			}
			records := query.Answer
			if test.minimum != 0 {
				if query.Ns[0].(*dns.SOA).Minttl != test.minimum {
					t.Fatal("SOA RDATA must not be rewritten")
				}
				records = query.Ns
			}
			if got := records[0].Header().Ttl; got != test.want {
				t.Fatalf("effective TTL=%d, want %d", got, test.want)
			}
			if opt := query.IsEdns0(); opt == nil || !opt.Do() || opt.UDPSize() != 1232 {
				t.Fatal("TTL aging changed EDNS flags")
			}
		})
	}
}
