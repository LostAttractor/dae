// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	dnsmessage "github.com/miekg/dns"
)

type routeTestBody struct {
	io.Reader
	closed atomic.Int32
}

func (b *routeTestBody) Close() error { b.closed.Add(1); return nil }

func TestHTTPRoutePlanConsumesCandidatesLazily(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4 succeeds", true: "IPv4 fails then IPv6"}[fallback], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "one-shot payload" {
					t.Errorf("request body = %q, %v", body, err)
				}
				_, _ = w.Write([]byte("ok"))
			}))
			defer server.Close()
			var aaaaQueries, ipv4Dials, ipv6Dials atomic.Int32
			group := downloadTestGroup(t, "direct", func(ctx context.Context, _, address string) (net.Conn, error) {
				if address == "198.51.100.1:80" {
					ipv4Dials.Add(1)
					if fallback {
						return nil, errors.New("IPv4 dial failed")
					}
				} else if address == "[2001:db8::1]:80" {
					ipv6Dials.Add(1)
				} else {
					t.Errorf("unexpected dial target %s", address)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			})
			plane := downloadTestPlane(t, "", group)
			attachDownloadTestDNS(t, plane, "", "", func(message *dnsmessage.Msg) {
				q := message.Question[0]
				if q.Qtype == dnsmessage.TypeA {
					message.Answer = []dnsmessage.RR{testARecord(q.Name, "198.51.100.1")}
				} else {
					aaaaQueries.Add(1)
					message.Answer = []dnsmessage.RR{&dnsmessage.AAAA{Hdr: dnsmessage.RR_Header{Name: q.Name, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
				}
			})
			planner := &httpRoutePlanner{plane: plane, network: "tcp"}
			client, closeClient := mitm.NewRoutedHTTPClient(planner.plan)
			defer closeClient()
			client.Timeout = 2 * time.Second
			for range 2 {
				body := &routeTestBody{Reader: strings.NewReader("one-shot payload")}
				r, err := http.NewRequestWithContext(t.Context(), "POST", "http://target.example/", body)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if body.closed.Load() != 1 {
					t.Fatalf("body closed %d times", body.closed.Load())
				}
			}
			if fallback {
				if ipv4Dials.Load() != 2 || ipv6Dials.Load() != 1 || aaaaQueries.Load() != 2 {
					t.Fatalf("fallback/pool reuse: IPv4=%d IPv6=%d AAAA=%d", ipv4Dials.Load(), ipv6Dials.Load(), aaaaQueries.Load())
				}
			} else if ipv4Dials.Load() != 1 || ipv6Dials.Load() != 0 || aaaaQueries.Load() != 0 {
				t.Fatalf("successful first route waited for more candidates: IPv4=%d IPv6=%d AAAA=%d", ipv4Dials.Load(), ipv6Dials.Load(), aaaaQueries.Load())
			}
		})
	}
}
