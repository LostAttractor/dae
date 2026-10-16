// SPDX-License-Identifier: AGPL-3.0-only

package mitmverify

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func (s *Service) Wrap(flow plugin.Flow, _ plugin.Handler) plugin.Handler {
	return func(exchange *plugin.Exchange) (*http.Response, error) {
		// Matching a Host header alone cannot produce an interception witness.
		if flow.Destination.Port() != 443 || !slices.Contains(s.targets[:], flow.Destination.Addr().Unmap()) ||
			flow.Host != flow.Destination.Addr().Unmap().String() || exchange.Request.URL.Scheme != "https" {
			return response(http.StatusForbidden, nil, "invalid test destination"), nil
		}
		return s.respond(exchange.Request, flow), nil
	}
}

func response(code int, header http.Header, body string) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	header.Set("Cache-Control", "no-store")
	header.Set("Connection", "close")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Close: true}
}

func (s *Service) respond(r *http.Request, flow plugin.Flow) *http.Response {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return response(http.StatusBadRequest, nil, "expected an empty GET challenge request")
	}
	id, ok := strings.CutPrefix(r.URL.Path, "/test/")
	if !ok {
		return response(http.StatusNotFound, nil, "test not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	test := s.tests[id]
	if test == nil || !test.MITMEnabled || flow.SourceMAC == [6]byte{} || flow.SourceMAC != test.mac {
		return response(http.StatusNotFound, nil, "test expired or belongs to another device")
	}
	want := test.mitm
	destination, err := netip.ParseAddrPort(r.Host)
	if err != nil {
		ip, _ := netip.ParseAddr(strings.Trim(r.Host, "[]"))
		destination = netip.AddrPortFrom(ip, 443)
	}
	actual := netip.AddrPortFrom(flow.Destination.Addr().Unmap(), flow.Destination.Port())
	if actual != want || destination != want || r.Header.Get("Origin") != test.origin {
		return response(http.StatusForbidden, nil, "test origin or destination does not match")
	}
	test.MITMObserved = true
	data, err := json.Marshal(api.MITMTestProof{ID: id, CAFingerprint: test.CAFingerprint})
	if err != nil {
		return response(http.StatusInternalServerError, nil, "encode test proof")
	}
	result := response(http.StatusOK, http.Header{"Content-Type": {"application/json"}, "Access-Control-Allow-Origin": {test.origin}, "Vary": {"Origin"}}, "")
	result.Body, result.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
	return result
}
