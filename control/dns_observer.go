// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

// Unpack accepts trailing bytes and some short sections. Such frames are still
// relayed verbatim, but must not trigger plugins or publish registry evidence.
func unpackDNSMessage(wire []byte) *dns.Msg {
	m := new(dns.Msg)
	if netutils.UnpackDnsMessage(wire, m) != nil {
		return nil
	}
	return m
}

// Observe only correlated, complete IN address responses. The wire message is
// never normalized or edited: DNSSEC, EDNS and upstream TTLs belong to endpoints.
func observeDNSRegistry(registry *DomainRegistry, match func(string) []uint32, request *plugin.DNSExchange, response *plugin.DNSResponse) {
	observeDNSRegistryAt(registry, match, request, response, time.Now())
}

func observeDNSRegistryAt(registry *DomainRegistry, match func(string) []uint32, request *plugin.DNSExchange, response *plugin.DNSResponse, deliveredAt time.Time) {
	if registry == nil || match == nil || request == nil || response == nil {
		return
	}
	m := response.MessageCopy()
	if !dnsResponseMatches(request.MessageCopy(), m) {
		return
	}
	if m.Opcode != dns.OpcodeQuery || m.Truncated || m.Rcode != dns.RcodeSuccess || len(m.Question) != 1 {
		return
	}
	q := m.Question[0]
	if q.Qclass != dns.ClassINET || q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return
	}
	at := deliveredAt
	type link struct {
		target string
		ttl    uint32
	}
	links := make(map[string]link)
	addresses := make(map[string][]dns.RR)
	for _, rr := range m.Answer {
		if rr == nil || rr.Header().Class != dns.ClassINET {
			continue
		}
		name := dns.CanonicalName(rr.Header().Name)
		if cname, ok := rr.(*dns.CNAME); ok {
			target := dns.CanonicalName(cname.Target)
			if old, exists := links[name]; exists {
				if old.target != target {
					return
				}
				links[name] = link{target, min(old.ttl, observedDNSTTL(cname.Hdr.Ttl))}
			} else {
				links[name] = link{target, observedDNSTTL(cname.Hdr.Ttl)}
			}
		} else if rr.Header().Rrtype == q.Qtype {
			addresses[name] = append(addresses[name], rr)
		}
	}
	names := []string{dns.CanonicalName(q.Name)}
	seen := map[string]bool{names[0]: true}
	for len(names) <= 16 {
		name := names[len(names)-1]
		l, ok := links[name]
		if !ok {
			break
		}
		if len(addresses[name]) != 0 || seen[l.target] {
			return
		}
		seen[l.target] = true
		names = append(names, l.target)
	}
	if len(names) > 16 {
		return
	}
	terminal := names[len(names)-1]
	rrs := addresses[terminal]
	if len(rrs) == 0 {
		return
	}
	ttl := uint32(1<<31 - 1)
	var ips []netip.Addr
	for _, rr := range rrs {
		ttl = min(ttl, observedDNSTTL(rr.Header().Ttl))
		var raw []byte
		switch rr := rr.(type) {
		case *dns.A:
			raw = rr.A
		case *dns.AAAA:
			raw = rr.AAAA
		}
		ip, ok := netip.AddrFromSlice(raw)
		if ok && !ip.IsUnspecified() && (q.Qtype == dns.TypeA && ip.Unmap().Is4() || q.Qtype == dns.TypeAAAA && ip.Is6() && !ip.Is4In6()) {
			ips = append(ips, ip.Unmap())
		}
	}
	if len(ips) == 0 {
		return
	}
	// Validate signature times at delivery. Retaining accepted historical
	// evidence does not claim that a signature remains valid afterwards.
	var observations []domainObservation
	for i := len(names) - 1; i >= 0; i-- {
		name := names[i]
		rrtype := q.Qtype
		if i != len(names)-1 {
			rrtype = dns.TypeCNAME
			ttl = min(ttl, links[name].ttl)
		}
		for _, rr := range m.Answer {
			sig, ok := rr.(*dns.RRSIG)
			if !ok || dns.CanonicalName(sig.Hdr.Name) != name || sig.TypeCovered != rrtype {
				continue
			}
			remaining, valid := rrsigRemainingTTL(sig, at)
			if !valid || remaining <= 0 {
				return
			}
		}
		observations = append(observations, domainObservation{name: name, ips: ips, ttl: int(ttl)})
	}
	// Validate the entire chain before publishing any terminal or alias evidence.
	for i := range observations {
		observations[i].bitmap = match(observations[i].name)
	}
	registry.ObserveDNS(observations, at)
}

// RFC 2181 section 8: high-bit TTLs mean zero. Normalize only the evidence
// calculation; the transparently delivered wire remains owned by the endpoints.
func observedDNSTTL(ttl uint32) uint32 {
	if ttl >= 1<<31 {
		return 0
	}
	return ttl
}

func dnsResponseMatches(request, response *dns.Msg) bool {
	if request == nil || response == nil || request.Response || !response.Response ||
		request.Id != response.Id || request.Opcode != response.Opcode || len(request.Question) != len(response.Question) {
		return false
	}
	for i, q := range request.Question {
		r := response.Question[i]
		if !strings.EqualFold(q.Name, r.Name) || q.Qtype != r.Qtype || q.Qclass != r.Qclass {
			return false
		}
	}
	return true
}

func rrsigRemainingTTL(signature *dns.RRSIG, at time.Time) (int, bool) {
	now := uint32(at.Unix())
	const halfRange = uint32(1) << 31
	if now-signature.Inception >= halfRange || signature.Expiration-now >= halfRange {
		return 0, false
	}
	remaining := signature.Expiration - now
	if at.Nanosecond() != 0 && remaining > 0 {
		remaining--
	}
	return int(remaining), true
}
