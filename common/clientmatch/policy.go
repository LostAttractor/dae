// SPDX-License-Identifier: AGPL-3.0-only

package clientmatch

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
)

// Decision retains source order across IP, MAC and all selectors. Zero Order
// is reserved for explicit overrides; configured entries start at one.
type Decision struct {
	Order uint32
	Allow bool
}

// Entry is a compiled client rule. Exactly one of Prefix, MAC or All is set.
// Override identifies a dynamic MAC preference, preceding every static rule.
type Entry struct {
	Prefix   netip.Prefix
	MAC      [6]byte
	All      bool
	Override bool
	Decision Decision
}

// Policy is an immutable compiled view shared by userspace admission and the
// kernel publisher. Prefix values already account for earlier broader rules,
// so a longest-prefix lookup preserves first-match semantics.
type Policy struct {
	prefixes  map[netip.Prefix]Decision
	macs      map[[6]byte]Decision
	overrides map[[6]byte]bool
	fallback  Decision
}

func (m Matcher) Compile(overrides map[[6]byte]bool) *Policy {
	p := &Policy{prefixes: make(map[netip.Prefix]Decision), macs: make(map[[6]byte]Decision), overrides: maps.Clone(overrides), fallback: Decision{Order: ^uint32(0)}}
	for i, r := range m.rules {
		decision := Decision{Order: uint32(i + 1), Allow: !r.deny}
		switch {
		case r.all:
			if decision.Order < p.fallback.Order {
				p.fallback = decision
			}
		case r.isMAC:
			if r.mac == [6]byte{} {
				continue
			} // Unknown MAC never matches a selector.
			if _, exists := p.macs[r.mac]; !exists {
				p.macs[r.mac] = decision
			}
		default:
			if _, exists := p.prefixes[r.prefix]; !exists {
				p.prefixes[r.prefix] = decision
			}
		}
	}
	// Each configured prefix inherits the earliest covering IP rule. Keeping
	// narrower early rules in the trie lets them override a later broad rule.
	for prefix, decision := range p.prefixes {
		for bits := prefix.Bits() - 1; bits >= 0; bits-- {
			parent := netip.PrefixFrom(prefix.Addr(), bits).Masked()
			if ancestor, exists := p.prefixes[parent]; exists && ancestor.Order < decision.Order {
				decision = ancestor
			}
		}
		p.prefixes[prefix] = decision
	}
	return p
}

func (p *Policy) Match(source netip.Addr, mac [6]byte) (enabled bool, override *bool) {
	if p == nil {
		return false, nil
	}
	if mac != [6]byte{} {
		if enabled, exists := p.overrides[mac]; exists {
			return enabled, new(enabled)
		}
	}
	return p.Default(source, mac), nil
}

// Default is the configured decision for a client, ignoring its dynamic MAC
// override: the value a device returns to when its override is cleared.
func (p *Policy) Default(source netip.Addr, mac [6]byte) bool {
	if p == nil {
		return false
	}
	decision := p.fallback
	if mac != [6]byte{} {
		if candidate, exists := p.macs[mac]; exists && candidate.Order < decision.Order {
			decision = candidate
		}
	}
	source = source.WithZone("").Unmap()
	if source.IsValid() {
		for bits := source.BitLen(); bits >= 0; bits-- {
			if candidate, exists := p.prefixes[netip.PrefixFrom(source, bits).Masked()]; exists {
				if candidate.Order < decision.Order {
					decision = candidate
				}
				break
			}
		}
	}
	return decision.Allow
}

// Entries exports a stable value copy for kernel-map preparation. Mutating the
// result cannot change this policy or another configuration generation.
func (p *Policy) Entries() []Entry {
	entries := make([]Entry, 0, len(p.prefixes)+len(p.macs)+len(p.overrides)+1)
	if p.fallback.Order != ^uint32(0) {
		entries = append(entries, Entry{All: true, Decision: p.fallback})
	}
	for prefix, decision := range p.prefixes {
		entries = append(entries, Entry{Prefix: prefix, Decision: decision})
	}
	for mac, decision := range p.macs {
		entries = append(entries, Entry{MAC: mac, Decision: decision})
	}
	for mac, enabled := range p.overrides {
		if mac != [6]byte{} {
			entries = append(entries, Entry{MAC: mac, Override: true, Decision: Decision{Allow: enabled}})
		}
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		if order := cmp.Compare(a.Decision.Order, b.Decision.Order); order != 0 {
			return order
		}
		if order := a.Prefix.Compare(b.Prefix); order != 0 {
			return order
		}
		return slices.Compare(a.MAC[:], b.MAC[:])
	})
	return entries
}
