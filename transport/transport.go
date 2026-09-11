// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"

	dns "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type dialArgument struct {
	networkType common.NetworkType
	Dialer      netproxy.Dialer
	Target      netip.AddrPort
}

func (a *dialArgument) dialerForConnection() netproxy.Dialer { return a.Dialer }

func closeInBackground(conn io.Closer) {
	if conn != nil {
		go conn.Close()
	}
}

// New owns protocol transport and connection reuse, but never response caching.
func New(ctx context.Context, upstream *dns.Upstream, dialer netproxy.Dialer, target netip.AddrPort, protocol string) (DnsForwarder, error) {
	return newDnsForwarder(ctx, upstream, dialArgument{Dialer: dialer, Target: target,
		networkType: common.NetworkType{L4Proto: consts.L4ProtoStr(protocol), IpVersion: consts.IpVersionStrFromAddr(target.Addr())}})
}

func validateDNSResponseIdentity(request, response *dnsmessage.Msg) error {
	if request == nil || response == nil || !response.Response || request.Id != response.Id || request.Opcode != response.Opcode || len(request.Question) != len(response.Question) {
		return fmt.Errorf("DNS response identity mismatch")
	}
	for i, q := range request.Question {
		r := response.Question[i]
		if !strings.EqualFold(q.Name, r.Name) || q.Qtype != r.Qtype || q.Qclass != r.Qclass {
			return fmt.Errorf("DNS response question mismatch")
		}
	}
	return nil
}
