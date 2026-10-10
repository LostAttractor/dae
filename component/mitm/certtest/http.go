// SPDX-License-Identifier: AGPL-3.0-only

package certtest

import (
	"bytes"
	"crypto/tls"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

// Endpoint serves only CA challenges on the API listener's HTTPS branch.
// A positive MITM witness is produced exclusively by Wrap at a virtual target.
type Endpoint struct {
	Service *Service
}

func (e Endpoint) TLSGeneration() string { return e.Service.Generation() }

func (e Endpoint) TLSConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	local, ok := hello.Conn.LocalAddr().(*net.TCPAddr)
	if !ok || !slices.Contains(e.Service.hosts, local.AddrPort().Addr().Unmap()) {
		return nil, fmt.Errorf("certificate test requires a local IP")
	}
	configuration := e.Service.authority.TLSConfig(local.AddrPort().Addr().Unmap().String())
	configuration.SessionTicketsDisabled = true
	return configuration, nil
}

func (e Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if r.TLS == nil || !ok {
		http.Error(w, "certificate test requires TLS", http.StatusForbidden)
		return
	}
	source, _ := netip.ParseAddrPort(r.RemoteAddr)
	response := e.Service.respond(r, plugin.Flow{Source: source, Destination: local.AddrPort()}, "trust")
	defer response.Body.Close()
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (s *Service) Wrap(flow plugin.Flow, _ plugin.Handler) plugin.Handler {
	return func(exchange *plugin.Exchange) (*http.Response, error) {
		// Matching a Host header alone cannot produce an interception witness.
		if flow.Destination.Port() != 443 || !slices.Contains(s.targets[:], flow.Destination.Addr().Unmap()) ||
			flow.Host != flow.Destination.Addr().Unmap().String() || exchange.Request.URL.Scheme != "https" {
			return response(http.StatusForbidden, nil, "invalid test destination"), nil
		}
		return s.respond(exchange.Request, flow, "mitm"), nil
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

func (s *Service) respond(r *http.Request, flow plugin.Flow, stage string) *http.Response {
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
	if test == nil || stage == "trust" && flow.Source.Addr().Unmap() != test.ip || stage == "mitm" && (flow.SourceMAC == [6]byte{} || flow.SourceMAC != test.mac) {
		return response(http.StatusNotFound, nil, "test expired or belongs to another device")
	}
	want := test.mitm
	if stage == "trust" {
		want = test.trust
	}
	destination, err := netip.ParseAddrPort(r.Host)
	if err != nil {
		ip, _ := netip.ParseAddr(strings.Trim(r.Host, "[]"))
		destination = netip.AddrPortFrom(ip, 443)
	}
	actual := netip.AddrPortFrom(flow.Destination.Addr().Unmap(), flow.Destination.Port())
	if actual != want || destination != want || r.Header.Get("Origin") != test.origin {
		return response(http.StatusForbidden, nil, "test origin or destination does not match")
	}
	switch stage {
	case "trust":
		test.TrustObserved = true
	case "mitm":
		test.MITMObserved = true
	}
	data, err := json.Marshal(api.CertificateTestProof{ID: id, Stage: stage, CAFingerprint: test.CAFingerprint})
	if err != nil {
		return response(http.StatusInternalServerError, nil, "encode test proof")
	}
	result := response(http.StatusOK, http.Header{"Content-Type": {"application/json"}, "Access-Control-Allow-Origin": {test.origin}, "Vary": {"Origin"}}, "")
	result.Body, result.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
	return result
}
