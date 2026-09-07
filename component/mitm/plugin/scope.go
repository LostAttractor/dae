// SPDX-License-Identifier: AGPL-3.0-only
package plugin

import (
	"net/netip"
	"slices"
	"strings"
)

// Scope is an ordered allow/exclude list. The first matching rule wins;
// unmatched connections are excluded. Separate scopes are combined with OR.
type Scope []HostRule

type HostRule struct {
	// Host is a hostname glob (* and ?) or an unbracketed IP address, without
	// a port or an exclusion prefix. Matching is case-insensitive.
	Host string
	// Empty Ports matches all nonzero ports. Port zero itself is invalid.
	Ports   []uint16
	Exclude bool
}

func (s Scope) Match(host string, port uint16) bool {
	if host == "" || port == 0 {
		return false
	}
	host = scopeHost(host)
	for _, rule := range s {
		if len(rule.Ports) != 0 && !slices.Contains(rule.Ports, port) {
			continue
		}
		if glob(scopeHost(rule.Host), host) {
			return !rule.Exclude
		}
	}
	return false
}

func scopeHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	// Only IPv6 (including mapped IPv4) needs address normalization. Avoid
	// constructing a ParseAddr error for every ordinary hostname comparison.
	if strings.Contains(host, ":") {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.Unmap().String()
		}
	}
	return host
}

func glob(pattern, value string) bool {
	p, v, star, back := 0, 0, -1, 0
	for v < len(value) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]) {
			p++
			v++
			continue
		}
		if p < len(pattern) && pattern[p] == '*' {
			star = p
			p++
			back = v
			continue
		}
		if star < 0 {
			return false
		}
		p = star + 1
		back++
		v = back
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
