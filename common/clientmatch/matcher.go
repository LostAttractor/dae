/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// Package clientmatch matches ordered client IP, network, and Ethernet MAC selectors.
package clientmatch

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Matcher selects clients using the first matching entry. Its zero value and an
// empty list deny every client. Clients not matching any entry are also denied.
// A Matcher is safe for concurrent use.
type Matcher struct {
	rules []rule
}

type rule struct {
	prefix netip.Prefix
	mac    [6]byte
	isMAC  bool
	all    bool
	deny   bool
}

// Parse accepts "all", IP addresses, CIDR prefixes, and six-byte Ethernet MAC
// addresses. A leading '-' excludes a matching client. Entries are considered
// in order, including when different kinds of rules match the same client.
//
// IPv4-mapped addresses and mapped prefixes of at least 96 bits are normalized
// to IPv4. Broader mapped prefixes are rejected because they cross into native
// IPv6 space. Native IPv6 prefixes match only IPv6 clients; IPv4 clients require
// an IPv4 selector, so ::/0 and 0.0.0.0/0 select different address families.
func Parse(entries []string) (Matcher, error) {
	if len(entries) == 0 {
		return Matcher{}, nil
	}
	m := Matcher{rules: make([]rule, 0, len(entries))}
	for i, raw := range entries {
		entry := strings.TrimSpace(raw)
		deny := strings.HasPrefix(entry, "-")
		if deny {
			entry = strings.TrimSpace(strings.TrimPrefix(entry, "-"))
		}
		if entry == "" {
			return Matcher{}, fmt.Errorf("client selector %d: empty entry", i+1)
		}
		if strings.Contains(entry, ",") {
			return Matcher{}, fmt.Errorf("client selector %d %q: comma-separated entries must be supplied separately", i+1, raw)
		}
		r, err := parseRule(entry)
		if err != nil {
			return Matcher{}, fmt.Errorf("client selector %d %q: %w", i+1, raw, err)
		}
		r.deny = deny
		m.rules = append(m.rules, r)
	}
	return m, nil
}

func parseRule(entry string) (rule, error) {
	if entry == "all" {
		return rule{all: true}, nil
	}
	if addr, err := netip.ParseAddr(entry); err == nil {
		if addr.Zone() != "" {
			return rule{}, fmt.Errorf("IP zones are not supported")
		}
		addr = addr.Unmap()
		return rule{prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
	}
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return rule{}, fmt.Errorf("IPv4-mapped CIDR must have at least 96 prefix bits; use separate IPv4 and IPv6 selectors")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return rule{prefix: prefix.Masked()}, nil
	}
	if mac, err := net.ParseMAC(entry); err == nil {
		if len(mac) != 6 {
			return rule{}, fmt.Errorf("MAC address must contain exactly 6 bytes")
		}
		return rule{mac: [6]byte(mac), isMAC: true}, nil
	}
	return rule{}, fmt.Errorf("expected all, an IP address, CIDR prefix, or 6-byte Ethernet MAC address")
}

// Match reports whether the client is selected. Observed IPv4-mapped addresses
// are normalized to IPv4, and an observed IPv6 zone is ignored. An all-zero MAC
// means that the MAC is unknown and never matches a MAC rule; IP rules still
// apply. An invalid source address never matches an IP rule. The all selector
// matches even when both identities are unknown.
func (m Matcher) Match(source netip.Addr, mac [6]byte) bool {
	source = source.WithZone("").Unmap()
	for _, r := range m.rules {
		if r.all {
			return !r.deny
		} else if r.isMAC {
			if mac != ([6]byte{}) && r.mac == mac {
				return !r.deny
			}
		} else if r.prefix.Contains(source) {
			return !r.deny
		}
	}
	return false
}
