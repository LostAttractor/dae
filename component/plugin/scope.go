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
	_, allowed := s.Decide(host, port)
	return allowed
}

// Decide returns the first matching rule and its allow/exclude decision.
// An index of -1 means no rule matches.
func (s Scope) Decide(host string, port uint16) (int, bool) {
	if host == "" || port == 0 {
		return -1, false
	}
	host = scopeHost(host)
	for i, rule := range s {
		if rule.matches(host, port) {
			return i, !rule.Exclude
		}
	}
	return -1, false
}

// Match reports the rule predicate, independently of its allow/exclude action.
func (r HostRule) Match(host string, port uint16) bool {
	return host != "" && port != 0 && r.matches(scopeHost(host), port)
}

func (r HostRule) matches(host string, port uint16) bool {
	return (len(r.Ports) == 0 || slices.Contains(r.Ports, port)) && glob(scopeHost(r.Host), host)
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
