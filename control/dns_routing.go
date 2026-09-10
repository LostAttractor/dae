/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

// A nil registry creates a resolver for preparation only: DNS policy and cache
// still work, but accepted answers cannot modify the shared kernel domain map.
func (c *ControlPlane) newDNSController(conf *config.Dns, rules preparedRules, registry *DomainRegistry) (controller *DnsController, err error) {
	upstreams, err := dns.New(conf, rules.dnsRequest, rules.dnsResponse, &dns.NewOption{
		UpstreamReadyCallback: func(upstream *dns.Upstream) { controller.cacheUpstream(upstream) },
		InterfaceManager:      c.core.ifmgr,
	})
	if err != nil {
		return nil, err
	}
	if err := upstreams.CheckUpstreamsFormat(); err != nil {
		return nil, err
	}
	fixedDomainTTL, err := ParseFixedDomainTtl(conf.FixedDomainTtl)
	if err != nil {
		return nil, err
	}
	return NewDnsController(upstreams, &DnsControllerOption{
		MatchBitmap:       c.routingMatcher.domainMatcher.MatchDomainBitmap,
		DomainRegistry:    registry,
		BestDialerChooser: c.chooseBestDnsDialer,
		IpVersionPrefer:   conf.IpVersionPrefer,
		FixedDomainTtl:    fixedDomainTTL,
		SoMarkFromDae:     c.soMarkFromDae,
		InterfaceName:     c.interfaceName,
	})
}

func ParseFixedDomainTtl(ks []config.KeyableString) (map[string]int, error) {
	m := make(map[string]int)
	for _, k := range ks {
		key, value, _ := strings.Cut(string(k), ":")
		key = dnsmessage.CanonicalName(strings.TrimSpace(key))
		ttl, err := strconv.ParseUint(strings.TrimSpace(value), 0, 31)
		if err != nil {
			return nil, oops.Errorf("failed to parse ttl: %v", err)
		}
		m[key] = int(ttl)
	}
	return m, nil
}

func (c *DnsController) cacheUpstream(dnsUpstream *dns.Upstream) {
	// Register resolved upstream addresses without expiry so hostname-based
	// domain routing remains valid for the upstream's lifetime.
	fqdn := dnsmessage.CanonicalName(dnsUpstream.Hostname)

	if dnsUpstream.Ip4.IsValid() {
		c.registerAddressNoExpiry(
			queryInfo{qname: fqdn, qtype: dnsmessage.TypeA}, dnsUpstream.Ip4,
		)
	}

	if dnsUpstream.Ip6.IsValid() {
		c.registerAddressNoExpiry(
			queryInfo{qname: fqdn, qtype: dnsmessage.TypeAAAA}, dnsUpstream.Ip6,
		)
	}
}

func (c *ControlPlane) chooseBestDnsDialer(
	req *udpRequest,
	dnsUpstream *dns.Upstream,
) (*dialArgument, error) {
	/// Choose the best l4proto+ipversion dialer, and change taregt DNS to the best ipversion DNS upstream for DNS request.
	// Get available ipversions and l4protos for DNS upstream.
	ipversions, l4protos := dnsUpstream.SupportedNetworks()
	var (
		bestNetworkType   common.NetworkType
		bestDialer        *dialer.Dialer
		bestOutbound      *outbound.DialerGroup
		bestOutboundIndex consts.OutboundIndex
		bestTarget        netip.AddrPort
		dialMark          uint32
	)
	var networkType common.NetworkType
	// Get the first available path in upstream preference order.
	searching := true
	for _, ver := range ipversions {
		for _, proto := range l4protos {
			networkType.L4Proto = proto
			networkType.IpVersion = ver
			var dAddr netip.Addr
			switch ver {
			case consts.IpVersionStr_4:
				dAddr = dnsUpstream.Ip4
			case consts.IpVersionStr_6:
				dAddr = dnsUpstream.Ip6
			default:
				return nil, oops.Errorf("unexpected ipversion: %v", ver)
			}
			target := netip.AddrPortFrom(dAddr, dnsUpstream.Port)
			outboundIndex, mark, _, err := c.Route(req.src, target, dnsUpstream.Hostname, proto.ToL4ProtoType(), req.routingResult)
			if err != nil {
				return nil, err
			}
			if int(outboundIndex) >= len(c.outbounds) {
				return nil, oops.Errorf("bad outbound index: %v", outboundIndex)
			}
			dialerGroup := c.outbounds[outboundIndex]
			// DNS always dial IP.
			d, err := dialerGroup.Select(&networkType)
			if err != nil {
				continue
			}
			bestDialer = d
			bestOutbound = dialerGroup
			bestOutboundIndex = outboundIndex
			bestNetworkType = networkType
			bestTarget = target
			dialMark = mark
			searching = false
			break
		}
		if !searching {
			break
		}
	}
	if bestDialer == nil {
		return nil, oops.Errorf("no proper dialer for DNS upstream: %v", dnsUpstream.String())
	}
	if log.IsLevelEnabled(log.TraceLevel) {
		log.WithFields(log.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
			"upstream":   dnsUpstream.String(),
			"choose":     string(bestNetworkType.L4Proto) + "+" + string(bestNetworkType.IpVersion),
			"use":        bestTarget.String(),
			"outbound":   bestOutbound.Name,
			"dialer":     bestDialer.Name,
		}).Traceln("Choose DNS path")
	}
	return &dialArgument{
		networkType:      bestNetworkType,
		Dialer:           bestDialer,
		connectionDialer: c.directDialerForMark(bestOutboundIndex, dialMark),
		Outbound:         bestOutbound,
		Target:           bestTarget,
		Mark:             dialMark,
	}, nil
}
