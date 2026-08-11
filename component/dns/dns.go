/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
)

var ErrBadUpstreamFormat = fmt.Errorf("bad upstream format")

type Dns struct {
	upstream    []*UpstreamResolver
	reqMatcher  *RequestMatcher
	respMatcher *ResponseMatcher
}

type NewOption struct {
	LocationFinder        *assets.LocationFinder
	UpstreamReadyCallback func(dnsUpstream *Upstream)
	// InterfaceManager resolves ifname in request routing rules to ifindex and
	// keeps it in sync with the interface lifecycle. It may be nil, in which
	// case ifname rules never match.
	InterfaceManager *component.InterfaceManager
}

func New(dns *config.Dns, opt *NewOption) (s *Dns, err error) {
	s = &Dns{}
	// Parse upstream.
	upstreamName2Id := map[string]uint8{}
	for i, upstreamRaw := range dns.Upstream {
		if i >= int(consts.DnsRequestOutboundIndex_UserDefinedMax) ||
			i >= int(consts.DnsResponseOutboundIndex_UserDefinedMax) {
			return nil, fmt.Errorf("too many upstreams")
		}

		tag, link := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if tag == "" {
			return nil, fmt.Errorf("%w: '%v' has no tag", ErrBadUpstreamFormat, upstreamRaw)
		}
		var u *url.URL
		u, err = url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
		}
		r := &UpstreamResolver{
			Raw:                u,
			FinishInitCallback: opt.UpstreamReadyCallback,
		}
		upstreamName2Id[tag] = uint8(len(s.upstream))
		s.upstream = append(s.upstream, r)
	}
	// Optimize routings.
	if dns.Routing.Request.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Request.Rules,
		&routing.DatReaderOptimizer{LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}
	if dns.Routing.Response.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Response.Rules,
		&routing.DatReaderOptimizer{LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}
	// Parse request routing.
	reqMatcherBuilder, err := NewRequestMatcherBuilder(dns.Routing.Request.Rules, upstreamName2Id, dns.Routing.Request.Fallback, opt.InterfaceManager)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
	}
	s.reqMatcher, err = reqMatcherBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
	}
	// Parse response routing.
	respMatcherBuilder, err := NewResponseMatcherBuilder(dns.Routing.Response.Rules, upstreamName2Id, dns.Routing.Response.Fallback)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	s.respMatcher, err = respMatcherBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	return s, nil
}

func (s *Dns) CheckUpstreamsFormat() error {
	for _, upstream := range s.upstream {
		_, _, _, _, err := ParseRawUpstream(upstream.Raw)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Dns) GetUpstream(ctx context.Context, upstreamIndex consts.DnsRequestOutboundIndex) (upstream *Upstream, err error) {
	if upstreamIndex < 0 {
		return nil, fmt.Errorf("bad upstream index: %v is negative", upstreamIndex)
	}
	if int(upstreamIndex) >= len(s.upstream) {
		return nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
	}
	return s.upstream[upstreamIndex].GetUpstream(ctx)
}

func (s *Dns) RequestSelect(
	qname string,
	qtype uint16,
	ifindex uint32,
	dip netip.Addr,
	sip netip.Addr,
) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	return s.reqMatcher.Match(qname, qtype, ifindex, dip, sip)
}

func (s *Dns) ResponseSelect(msg *dnsmessage.Msg, from consts.DnsRequestOutboundIndex) (upstreamIndex consts.DnsResponseOutboundIndex, err error) {
	if !msg.Response {
		return 0, fmt.Errorf("DNS response expected but DNS request received")
	}

	// Prepare routing.
	var qname string
	var qtype uint16
	var ips []netip.Addr
	if len(msg.Question) == 0 {
		qname = ""
		qtype = 0
	} else {
		q := msg.Question[0]
		qname = q.Name
		qtype = q.Qtype
		for _, ans := range msg.Answer {
			var (
				ip netip.Addr
				ok bool
			)
			switch body := ans.(type) {
			case *dnsmessage.A:
				ip, ok = netip.AddrFromSlice(body.A)
			case *dnsmessage.AAAA:
				ip, ok = netip.AddrFromSlice(body.AAAA)
			}
			if !ok {
				continue
			}
			ips = append(ips, ip)
		}
	}

	// Route.
	upstreamIndex, err = s.respMatcher.Match(qname, qtype, ips, from)
	if err != nil {
		return 0, err
	}
	return upstreamIndex, nil
}
