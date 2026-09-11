// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dns "github.com/miekg/dns"
)

type HostEntry struct {
	Pattern            string
	Addresses          []netip.Addr
	Alias, Script      string
	Servers            []string
	SetKind, SetSource string
	Rules              []ModuleRule
}

func (h HostEntry) Match(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if h.SetKind == "" {
		return (plugin.Scope{{Host: h.Pattern}}).Match(name, 53)
	}
	for _, rule := range h.Rules {
		for _, clause := range rule.clauses {
			matched := true
			for _, p := range clause {
				var yes bool
				switch p.Type {
				case "DOMAIN":
					yes = name == p.Value
				case "DOMAIN-SUFFIX":
					yes = name == p.Value || strings.HasSuffix(name, "."+p.Value)
				case "DOMAIN-KEYWORD":
					yes = strings.Contains(name, p.Value)
				case "DOMAIN-WILDCARD":
					yes = (plugin.Scope{{Host: p.Value}}).Match(name, 53)
				default:
					// DNS has no IP/port/process context for a Host set. An
					// unsupported predicate cannot become a hit by negation.
					matched = false
				}
				if !matched || yes == p.Not {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func parseHost(line string, m *Module) error {
	key, value, ok := strings.Cut(line, "=")
	if strings.HasPrefix(line, "DOMAIN-SET:") || strings.HasPrefix(line, "RULE-SET:") {
		// URLs may contain '=' on either side. A whitespace-delimited '='
		// unambiguously separates a resource URL from its Host target. Compact
		// set=target syntax remains available for sources without '='.
		for i := 1; i+1 < len(line); i++ {
			if line[i] == '=' && strings.ContainsRune(" \t", rune(line[i-1])) && strings.ContainsRune(" \t", rune(line[i+1])) {
				key, value, ok = line[:i], line[i+1:], true
				break
			}
		}
	}
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if !ok || key == "" || value == "" {
		return fmt.Errorf("Host requires a non-empty matcher and target")
	}
	host := HostEntry{Pattern: strings.TrimSuffix(strings.ToLower(key), ".")}
	if kind, source, ok := strings.Cut(key, ":"); ok && (kind == "DOMAIN-SET" || kind == "RULE-SET") {
		host.SetKind, host.SetSource = kind, source
	} else if source, err := netip.ParseAddr(key); err == nil && source.Zone() == "" {
		mapping := routing.DestinationRewrite{Filter: []*config_parser.Function{{Name: "dip", Params: []*config_parser.Param{{Val: source.Unmap().String()}}}}}
		for _, target := range strings.Split(value, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(target))
			if err != nil || ip.Zone() != "" {
				return fmt.Errorf("IP Host mapping requires literal target IPs")
			}
			mapping.To = append(mapping.To, ip.Unmap())
		}
		m.Hosts = append(m.Hosts, mapping)
		return nil
	} else if strings.ContainsAny(key, "/:\\= \t\r\n[]") {
		return fmt.Errorf("invalid Host matcher %q", key)
	}
	switch {
	case strings.HasPrefix(value, "server:"):
		for _, server := range strings.Split(strings.TrimPrefix(value, "server:"), ",") {
			server = strings.TrimSpace(server)
			if err := validateHostServer(server); err != nil {
				return err
			}
			host.Servers = append(host.Servers, server)
		}
		if len(host.Servers) > 16 {
			return fmt.Errorf("Host permits at most 16 DNS servers")
		}
	case strings.HasPrefix(value, "script:"):
		host.Script = strings.TrimSpace(strings.TrimPrefix(value, "script:"))
		if host.Script == "" {
			return fmt.Errorf("empty DNS script name")
		}
	default:
		for _, target := range strings.Split(value, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(target))
			if err != nil || ip.Zone() != "" {
				if !strings.Contains(value, ",") {
					if _, ok := dns.IsDomainName(value); ok && !strings.ContainsAny(value, "*?:/ ") {
						host.Alias = dns.CanonicalName(value)
						break
					}
				}
				return fmt.Errorf("invalid Host target %q", value)
			}
			host.Addresses = append(host.Addresses, ip.Unmap())
		}
	}
	m.DNSHosts = append(m.DNSHosts, host)
	return nil
}

func validateHostServer(server string) error {
	switch server {
	case "system", "syslib", "force-syslib":
		return nil
	}
	if ip, err := netip.ParseAddr(server); err == nil && ip.Zone() == "" {
		return nil
	}
	if addr, err := netip.ParseAddrPort(server); err == nil && addr.Port() != 0 && addr.Addr().Zone() == "" {
		return nil
	}
	u, err := url.Parse(server)
	if err == nil && u.Hostname() != "" && u.User == nil {
		switch u.Scheme {
		case "udp", "tcp", "tcp+udp", "udp+tcp", "tls", "https", "quic", "h3", "http3":
			return nil
		}
	}
	return fmt.Errorf("invalid Host DNS server %q", server)
}
