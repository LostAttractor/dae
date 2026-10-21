// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	dns "github.com/miekg/dns"
)

func TestCheckDNSRefreshesOnlyRequestedFamily(t *testing.T) {
	previous := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = previous })
	var octet, queries atomic.Uint32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			conn := &dns.Conn{Conn: peer}
			request, err := conn.ReadMsg()
			if err != nil {
				return
			}
			queries.Add(1)
			q := request.Question[0]
			if q.Qtype != dns.TypeA {
				t.Errorf("IPv4 check queried type %d", q.Qtype)
			}
			reply := new(dns.Msg).SetReply(request)
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.IPv4(192, 0, 2, byte(octet.Load()))}}
			_ = conn.WriteMsg(reply)
		}()
		return client, nil
	}}
	options := CheckDnsOptionRaw{Raw: []string{"rotating-resolver.test.:53"}}
	for _, value := range []uint32{1, 2} {
		octet.Store(value)
		option, err := options.Option(t.Context(), consts.IpVersionStr_4)
		if err != nil {
			t.Fatal(err)
		}
		if option.Ip4.As4()[3] != byte(value) || option.Ip6.IsValid() {
			t.Fatalf("check addresses=%+v", option.Ip46)
		}
	}
	before := queries.Load()
	options.Raw = append(options.Raw, "192.0.2.53", "2001:db8::53")
	option, err := options.Option(t.Context(), consts.IpVersionStr_6)
	if err != nil || option.Ip6.String() != "2001:db8::53" || queries.Load() != before {
		t.Fatalf("explicit addresses were resolved: option=%v error=%v", option, err)
	}
}

func TestConnectivityProbesPreserveFailureCause(t *testing.T) {
	for _, selection := range []bool{false, true} {
		name := "background"
		if selection {
			name = "selection"
		}
		t.Run(name, func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			cause := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}
			checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
				return cause
			})
			defer checker.stopRetries()
			var result checkResult
			if selection {
				result = checker.performSelectionCheck(&selectionCheck{ctx: t.Context(), network: common.NetworkTCP4}, 0)
			} else {
				result = checkResult{probes: []probeResult{checker.runProbe(t.Context(), common.NetworkTCP4)}}
			}
			failure := result.failure()
			if !errors.Is(failure, syscall.ENETUNREACH) {
				t.Fatalf("probe discarded its failure cause: %v", failure)
			}
			if operation, ok := errors.AsType[*net.OpError](failure); !ok || operation != cause {
				t.Fatalf("probe discarded its operation metadata: %v", failure)
			}
		})
	}
}

func TestMissingResolverFamilyDoesNotDeclarePathUnsupported(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.CheckDnsOptionRaw.Raw = []string{"resolver.example:53", "192.0.2.1"}
	checker := newConnectivityChecker(d.pathRuntime, d.checkDNSConnectivity)
	defer checker.stopRetries()
	probe := checker.runProbe(t.Context(), common.NetworkTCP6)
	if probe.err == nil || !strings.Contains(probe.err.Error(), "no IPv6 address") {
		t.Fatalf("missing resolver family was not reported: %v", probe.err)
	}
	d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{probe}})
	status := d.RuntimeStatus()
	if status.Healthy || status.SupportState[common.NetworkTCP6] != api.NetworkSupportUnknown {
		t.Fatalf("local resolver configuration changed remote capability: %+v", status)
	}
}
