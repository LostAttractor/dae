// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func (e *Engine) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		message := request.MessageCopy()
		if message == nil || message.Response || message.Opcode != dns.OpcodeQuery || len(message.Question) != 1 || message.Question[0].Qclass != dns.ClassINET {
			return next(ctx, request)
		}
		qtype := message.Question[0].Qtype
		if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR || qtype == dns.TypeTKEY {
			return next(ctx, request)
		}
		for _, rr := range message.Extra {
			if rr.Header().Rrtype == dns.TypeTSIG || rr.Header().Rrtype == dns.TypeSIG {
				return next(ctx, request)
			}
		}
		return e.resolveHost(ctx, request, next, make(map[string]bool))
	}
}

func (e *Engine) findDNSHost(name string) (*Module, *HostEntry) {
	for _, module := range e.options.Modules {
		for i := range module.DNSHosts {
			host := &module.DNSHosts[i]
			if host.Match(name) {
				return module, host
			}
		}
	}
	return nil, nil
}

func (e *Engine) UseDNSAddress(name string, proxy bool) (use, applicable bool) {
	module, host := e.findDNSHost(name)
	if host == nil {
		return false, false
	}
	if proxy && !module.UseHostsForProxy {
		return false, true
	}
	for range 16 {
		if len(host.Addresses) != 0 {
			return true, true
		}
		if host.Alias == "" {
			return false, true
		}
		_, host = e.findDNSHost(host.Alias)
		if host == nil {
			return false, true
		}
	}
	return false, true
}

func (e *Engine) resolveHost(ctx context.Context, request *plugin.DNSExchange, next plugin.DNSHandler, seen map[string]bool) (*plugin.DNSResponse, error) {
	query := request.MessageCopy()
	q := query.Question[0]
	name := dns.CanonicalName(q.Name)
	if seen[name] || len(seen) >= 16 {
		return nil, fmt.Errorf("Host alias loop or depth limit at %s", name)
	}
	seen[name] = true
	module, host := e.findDNSHost(name)
	if host == nil {
		return next(ctx, request)
	}
	if len(host.Addresses) > 0 {
		return hostAddressResponse(request, host.Addresses, 60), nil
	}
	if host.Alias != "" {
		cname := &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: host.Alias}
		if q.Qtype == dns.TypeCNAME {
			response := hostAddressResponse(request, nil, 60)
			message := response.MessageCopy()
			message.Answer = []dns.RR{cname}
			response.DNSPacket = plugin.DNSMessage(message)
			return response, nil
		}
		alias := request.Copy()
		aliasQuery := query.Copy()
		aliasQuery.Question[0].Name = host.Alias
		alias.DNSPacket = plugin.DNSMessage(aliasQuery)
		response, err := e.resolveHost(ctx, alias, next, seen)
		if err != nil || response == nil {
			return response, err
		}
		response = response.Copy()
		// The relay intentionally forwards uncorrelated datagrams. Rewriting
		// must never turn one into an answer for the original client query.
		message := response.MessageCopy()
		if message == nil {
			return nil, fmt.Errorf("Host alias returned an empty DNS response")
		}
		if err := netutils.ValidateDnsResponseAllowEmptyQuestion(aliasQuery, message, aliasQuery.Id); err != nil {
			return nil, err
		}
		message.Id = query.Id
		message.Question = query.Question
		message.AuthenticatedData = false
		for _, rr := range message.Answer {
			cname.Hdr.Ttl = min(cname.Hdr.Ttl, rr.Header().Ttl)
		}
		message.Answer = append([]dns.RR{cname}, message.Answer...)
		response.DNSPacket = plugin.DNSMessage(message)
		return response, nil
	}
	if host.Script != "" {
		return e.runDNSScript(ctx, module, host.Script, request, next)
	}
	return resolveHostServers(ctx, request, host.Servers, next)
}

func hostAddressResponse(request *plugin.DNSExchange, addresses []netip.Addr, ttl uint32) *plugin.DNSResponse {
	query := request.MessageCopy()
	m := new(dns.Msg).SetReply(query)
	m.Authoritative, m.RecursionAvailable = true, true
	q := query.Question[0]
	for _, ip := range addresses {
		if ip.Is4() && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IP(ip.AsSlice())})
		} else if ip.Is6() && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: net.IP(ip.AsSlice())})
		}
	}
	return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(m), ReceivedAt: time.Now(), Origin: "surge:host"}
}

func resolveHostServers(ctx context.Context, request *plugin.DNSExchange, servers []string, next plugin.DNSHandler) (*plugin.DNSResponse, error) {
	if len(servers) == 1 {
		switch servers[0] {
		case "system", "syslib", "force-syslib":
			q := request.MessageCopy().Question[0]
			network := "ip"
			if q.Qtype == dns.TypeA {
				network = "ip4"
			} else if q.Qtype == dns.TypeAAAA {
				network = "ip6"
			} else {
				return resolveSystemDNS(ctx, request)
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, network, q.Name)
			if err != nil {
				if dnsErr, ok := errors.AsType[*net.DNSError](err); ok && dnsErr.IsNotFound {
					// LookupNetIP collapses NXDOMAIN and NODATA. Retrieve the
					// protocol response to preserve its rcode and authority.
					return resolveSystemDNS(ctx, request)
				}
				return nil, err
			}
			return hostAddressResponse(request, ips, 0), nil
		}
		// A plain per-domain server assignment just redirects the intercepted
		// request. More advanced transports are provided by the resolver plugin.
		target, err := netip.ParseAddrPort(servers[0])
		if ip, ipErr := netip.ParseAddr(servers[0]); ipErr == nil {
			target, err = netip.AddrPortFrom(ip, 53), nil
		}
		if err == nil {
			redirected := request.Copy()
			redirected.Destination = target
			redirected.ServerAssigned = true
			redirected.ContextKey += "/surge-server/" + target.String()
			return next(ctx, redirected)
		}
	}
	if request.Resolve == nil {
		return nil, fmt.Errorf("Host server assignment requires a DNS resolver plugin")
	}
	return request.Resolve(ctx, request, servers)
}

// Go's system resolver handles address lookups (including /etc/hosts). Other
// record types use the configured OS nameserver with the same marked Dial hook.
func resolveSystemDNS(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	if len(conf.Servers) == 0 {
		return nil, fmt.Errorf("system resolver has no nameservers")
	}
	dial := net.DefaultResolver.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, request.Network, net.JoinHostPort(conf.Servers[0], conf.Port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	message, _, err := (&dns.Client{Net: request.Network}).ExchangeWithConnContext(ctx, request.MessageCopy(), &dns.Conn{Conn: conn})
	if err != nil {
		return nil, err
	}
	return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message), ReceivedAt: time.Now(), Origin: "surge:system"}, nil
}

func (e *Engine) runDNSScript(ctx context.Context, module *Module, name string, request *plugin.DNSExchange, next plugin.DNSHandler) (*plugin.DNSResponse, error) {
	var script *Script
	for i := range module.Scripts {
		if module.Scripts[i].Name == name && module.Scripts[i].Type == "dns" {
			script = &module.Scripts[i]
			break
		}
	}
	if script == nil {
		return nil, fmt.Errorf("missing DNS script %q", name)
	}
	ctx, cancel := context.WithTimeout(ctx, e.scriptTimeout(script))
	defer cancel()
	release, err := e.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	result, err := e.options.Runtime.Run(ctx, script.Source, Invocation{Domain: strings.TrimSuffix(request.MessageCopy().Question[0].Name, "."),
		ScriptName: script.Name, ScriptType: "dns", Argument: script.Argument, Timeout: e.scriptTimeout(script),
		HTTPClient: request.Client, BodyMemory: e.options.BodyMemory, BodyLimit: e.options.MaxBodySize})
	if err != nil {
		return nil, err
	}
	defer result.Close()
	value := result.DNS
	forms := 0
	if value.Address != "" {
		forms++
	}
	if value.Addresses != nil {
		forms++
	}
	if value.Server != "" {
		forms++
	}
	if value.Servers != nil {
		forms++
	}
	if forms == 0 {
		return next(ctx, request)
	}
	if forms != 1 {
		return nil, fmt.Errorf("DNS script must return exactly one address/addresses/server/servers field")
	}
	if value.Address != "" {
		value.Addresses = []string{value.Address}
	}
	if value.Server != "" {
		value.Servers = []string{value.Server}
	}
	if value.Servers != nil {
		for _, server := range value.Servers {
			if err := validateHostServer(server); err != nil {
				return nil, err
			}
		}
		return resolveHostServers(ctx, request, value.Servers, next)
	}
	if len(value.Addresses) > 256 {
		return nil, fmt.Errorf("DNS script returned more than 256 addresses")
	}
	var addresses []netip.Addr
	for _, raw := range value.Addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("DNS script returned invalid address %q", raw)
		}
		addresses = append(addresses, ip.Unmap())
	}
	var ttl uint32
	if value.TTL != nil {
		ttl = *value.TTL
	}
	return hostAddressResponse(request, addresses, ttl), nil
}
