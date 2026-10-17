// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsrouter "github.com/daeuniverse/dae/plugins/dns-router"
	"github.com/miekg/dns"
)

func TestHostServerRaceIsIndependentOfResolverPlugin(t *testing.T) {
	for _, rcodes := range [][3]int{
		{dns.RcodeServerFailure, dns.RcodeNameError, dns.RcodeNameError},
		{dns.RcodeNameError, dns.RcodeSuccess, dns.RcodeSuccess},
		{dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeServerFailure},
	} {
		for _, withRouter := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/router=%v", rcodes, withRouter), func(t *testing.T) {
				request := hostDNSRequest(t, "race.example.", dns.TypeA)
				answer := func(ctx context.Context, query *dns.Msg, target string) (*plugin.DNSResponse, error) {
					code := rcodes[0]
					if strings.HasPrefix(target, "[2001:db8::54]") {
						select {
						case <-time.After(20 * time.Millisecond):
						case <-ctx.Done():
							return nil, ctx.Err()
						}
						code = rcodes[1]
					}
					message := new(dns.Msg).SetReply(query)
					message.Rcode = code
					return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message)}, nil
				}
				if withRouter {
					sections, err := config_parser.Parse("router {}")
					if err != nil {
						t.Fatal(err)
					}
					factory, err := dnsrouter.Configure(plugin.Spec{Config: sections[0]})
					if err != nil {
						t.Fatal(err)
					}
					instance, err := factory(t.Context(), plugin.Services{})
					if err != nil {
						t.Fatal(err)
					}
					router := instance.(*dnsrouter.Router)
					t.Cleanup(func() { _ = router.Close() })
					request.Resolve = router.ResolveDNS
					request.DialContext = func(ctx context.Context, _, target, _ string) (net.Conn, error) {
						client, server := net.Pipe()
						go func() {
							defer server.Close()
							stop := context.AfterFunc(ctx, func() { _ = server.Close() })
							defer stop()
							wire := make([]byte, 65535)
							n, err := server.Read(wire)
							if err != nil {
								return
							}
							query := new(dns.Msg)
							if err := query.Unpack(wire[:n]); err != nil {
								t.Error(err)
								return
							}
							response, err := answer(ctx, query, target)
							if err == nil {
								wire, err := response.Wire()
								if err != nil {
									t.Error(err)
									return
								}
								_, _ = server.Write(wire)
							}
						}()
						return client, nil
					}
				}
				response, err := resolveHostServers(t.Context(), request, []string{"192.0.2.53", "2001:db8::54"}, func(ctx context.Context, query *plugin.DNSExchange) (*plugin.DNSResponse, error) {
					return answer(ctx, query.MessageCopy(), query.Destination.String())
				})
				if err != nil || response == nil || response.MessageCopy().Rcode != rcodes[2] {
					t.Fatalf("server preference changed with resolver plugin: response=%v err=%v", response, err)
				}
			})
		}
	}
}
