// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"slices"
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

func TestHTTPRaceRoutesEachAddress(t *testing.T) {
	for _, test := range []struct{ rules, dialed string }{
		{"dip('2001:db8::/32') -> block", "198.51.100.1:80"},
		{"domain(blocked.test) -> block", ""},
	} {
		t.Run(test.rules, func(t *testing.T) {
			var dialed []string
			dial := func(_ context.Context, _, address string) (net.Conn, error) {
				dialed = append(dialed, address)
				conn, peer := net.Pipe()
				_ = peer.Close()
				return conn, nil
			}
			plane := downloadTestPlane(t, test.rules, downloadTestGroup(t, "direct", dial), downloadTestGroup(t, "block", dial))
			attachDownloadTestDNS(t, plane, "", "", func(message *dnsmessage.Msg) {
				q := message.Question[0]
				if q.Qtype == dnsmessage.TypeA {
					message.Answer = []dnsmessage.RR{testARecord(q.Name, "198.51.100.1")}
				} else {
					message.Answer = []dnsmessage.RR{&dnsmessage.AAAA{Hdr: dnsmessage.RR_Header{Name: q.Name, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}}
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			conn, err := mitmClientDialContext(plane)(ctx, "tcp", "blocked.test:80")
			if test.dialed == "" {
				if _, blocked := errors.AsType[*routeBlocked](err); !blocked || len(dialed) != 0 {
					t.Fatalf("blocked target: err=%v dialed=%v", err, dialed)
				}
				return
			}
			if err != nil || len(dialed) != 1 || dialed[0] != test.dialed {
				t.Fatalf("blocked address: err=%v dialed=%v", err, dialed)
			}
			_ = conn.Close()
		})
	}
}

// The daemon resolves to route each address, but a proxy receives the name;
// addresses routed to one node therefore share a single dial.
func TestHTTPCandidatesShareProxiedName(t *testing.T) {
	unused := func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	plane := downloadTestPlane(t, "domain(named.test) -> proxy", downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused))
	plane.dialTargetOverride = true
	attachDownloadTestDNS(t, plane, "", "", func(message *dnsmessage.Msg) {
		q := message.Question[0]
		if q.Qtype == dnsmessage.TypeA {
			message.Answer = []dnsmessage.RR{testARecord(q.Name, "198.51.100.1")}
		} else {
			message.Answer = []dnsmessage.RR{&dnsmessage.AAAA{Hdr: dnsmessage.RR_Header{Name: q.Name, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}}
		}
	})
	var targets []string
	for option, err := range plane.httpRouteCandidates(t.Context(), "tcp", httpTarget{"named.test", 80}, netip.AddrPort{}, routingResult{}) {
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, option.DialTarget)
	}
	if !slices.Equal(targets, []string{"named.test:80"}) {
		t.Fatalf("proxied candidates = %v", targets)
	}
}

func (b *routeTestBody) Close() error { b.closed.Add(1); return nil }

func TestHTTPRoutePlanRacesConnections(t *testing.T) {
	for _, behavior := range []string{"IPv6 succeeds", "IPv6 fails", "IPv6 stalls"} {
		t.Run(behavior, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
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

				} else if address == "[2001:db8::1]:80" {
					ipv6Dials.Add(1)
					switch behavior {
					case "IPv6 fails":
						return nil, errors.New("IPv6 dial failed")
					case "IPv6 stalls":
						<-ctx.Done()
						return nil, ctx.Err()
					}
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
			for i := range 2 {
				body := &routeTestBody{Reader: strings.NewReader("one-shot payload")}
				r, err := http.NewRequestWithContext(t.Context(), "POST", "http://target.example/", body)
				if err != nil {
					t.Fatal(err)
				}
				var reused atomic.Bool
				r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}))
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if i == 1 && !reused.Load() {
					t.Fatal("winning route did not reuse its HTTP pool")
				}
				if body.closed.Load() != 1 {
					t.Fatalf("body closed %d times", body.closed.Load())
				}
			}
			if requests.Load() != 2 {
				t.Fatalf("POST requests = %d, want exactly 2", requests.Load())
			}
			if ipv6Dials.Load() == 0 || aaaaQueries.Load() == 0 {
				t.Fatal("IPv6 was not attempted")
			}
			if behavior == "IPv6 succeeds" && (ipv4Dials.Load() != 0 || ipv6Dials.Load() != 1) {
				t.Fatalf("fast IPv6/pool hit dialed more connections: IPv4=%d IPv6=%d", ipv4Dials.Load(), ipv6Dials.Load())
			}
			if behavior != "IPv6 succeeds" && ipv4Dials.Load() == 0 {
				t.Fatal("IPv4 fallback was starved")
			}
		})
	}
}
