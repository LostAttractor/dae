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
