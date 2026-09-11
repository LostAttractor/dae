// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestHandlerAltSvc(t *testing.T) {
	for _, test := range []struct {
		name, scheme, host string
		port               uint16
		values             []string
		want               string
	}{
		{name: "no advertisement"},
		{name: "same port", values: []string{`h3=":443"; ma=86400`}, want: `h3=":443"; ma=86400`},
		{name: "same host", values: []string{`h3="SERVICE.EXAMPLE.:00443"; persist=1; ma="60"`}, want: `h3=":443"; ma=60; persist=1`},
		{name: "custom origin port", port: 8443, values: []string{`h3=":8443"; ma=0`}, want: `h3=":8443"; ma=0`},
		{name: "literal IPv4", host: "192.0.2.1", values: []string{`h3="[::ffff:192.0.2.1]:443"`}, want: `h3=":443"`},
		{name: "literal IPv6", host: "2001:db8::1", values: []string{`h3="[2001:db8:0:0:0:0:0:1]:443"`}, want: `h3=":443"`},
		{name: "filter protocol versions", values: []string{`h3-29=":443", h3=":443"; ma=60, h2=":443"`}, want: `h3=":443"; ma=60`},
		{name: "multiple header fields", values: []string{`h2=":443"`, `h3=":443"; ma=60`}, want: `h3=":443"; ma=60`},
		{name: "quoted unknown parameter", values: []string{`h3=":443"; extension="comma,semi;quote\""; ma=60`}, want: `h3=":443"; ma=60`},
		{name: "escaped authority", values: []string{`h3="service\.example:443"`}, want: `h3=":443"`},
		{name: "unknown persistence value", values: []string{`h3=":443"; persist=2`}, want: `h3=":443"`},
		{name: "clear", values: []string{`clear`}, want: `clear`},
		{name: "clear wins", values: []string{`h3=":443"`, `clear`}, want: `clear`},
		{name: "mixed clear wins", values: []string{`h3=":443", clear`}, want: `clear`},
		{name: "plain HTTP", scheme: "http", values: []string{`h3=":443"`}},
		{name: "cross host", values: []string{`h3="outside.example:443"`}},
		{name: "cross declared host", values: []string{`h3="other.example:443"`}},
		{name: "cross declared port", values: []string{`h3=":8443"`}},
		{name: "cross undeclared port", values: []string{`h3=":9999"`}},
		{name: "unknown ALPN", values: []string{`h3-29=":443"`}},
		{name: "ALPN is case sensitive", values: []string{`H3=":443"`}},
		{name: "noncanonical ALPN encoding", values: []string{`h%33=":443"`}},
		{name: "unquoted authority", values: []string{`h3=:443`}},
		{name: "unterminated authority", values: []string{`h3=":443`}},
		{name: "unterminated extension", values: []string{`h3=":443"; extension="bad, h3=":443"`}},
		{name: "missing port", values: []string{`h3="service.example"`}},
		{name: "invalid port", values: []string{`h3=":+443"`}},
		{name: "port zero", values: []string{`h3=":0"`}},
		{name: "port overflow", values: []string{`h3=":65536"`}},
		{name: "authority with user info", values: []string{`h3="user@service.example:443"`}},
		{name: "authority with path", values: []string{`h3="service.example:443/path"`}},
		{name: "authority with query", values: []string{`h3="service.example:443?query"`}},
		{name: "bare parameter", values: []string{`h3=":443"; persist`}},
		{name: "invalid max age", values: []string{`h3=":443"; ma=-1`}},
		{name: "overflow max age", values: []string{`h3=":443"; ma=18446744073709551616`}},
		{name: "duplicate max age", values: []string{`h3=":443"; ma=0; ma=60`}},
		{name: "trailing garbage", values: []string{`h3=":443" garbage`}},
		{name: "invalid parameter delimiter", values: []string{`h3=":443"; ma=60 garbage`}},
		{name: "header newline", values: []string{"h3=\":443\"\r\nX-Evil: yes"}},
		{name: "discard malformed entry", values: []string{`h3=":443"; ma=no, h3=":443"; ma=60`}, want: `h3=":443"; ma=60`},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, scheme, port := test.host, test.scheme, test.port
			if host == "" {
				host = "service.example"
			}
			if scheme == "" {
				scheme = "https"
			}
			if port == 0 {
				port = 443
			}
			p := &testPlugin{
				plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{
					{Host: host, Ports: []uint16{443, 8443}},
					{Host: "other.example", Ports: []uint16{443}},
				}}}},
				wrap: func(plugin.Flow, plugin.Handler) plugin.Handler {
					return func(*plugin.Exchange) (*http.Response, error) {
						r := response("ok")
						for _, value := range test.values {
							r.Header.Add("Alt-Svc", value)
						}
						r.Header.Set("X-Upstream", "unchanged")
						return r, nil
					}
				},
			}
			h := testHost(t, Options{Authority: &mitmca.Authority{}}, Instance{ID: "test", Type: "test", Plugin: p})
			handler, closeHandler := h.Handler(scheme, host, port, nil)
			defer closeHandler()
			request := httptest.NewRequest(http.MethodGet, scheme+"://"+net.JoinHostPort(host, strconv.Itoa(int(port)))+"/", nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" || recorder.Header().Get("X-Upstream") != "unchanged" {
				t.Fatalf("response was altered: code=%d body=%q headers=%v", recorder.Code, recorder.Body.String(), recorder.Header())
			}
			if got := recorder.Header().Get("Alt-Svc"); got != test.want {
				t.Fatalf("Alt-Svc = %q, want %q", got, test.want)
			}
		})
	}
}
