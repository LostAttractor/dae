// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"slices"
	"time"
)

// A snapshot owns its maps and bitmap slices. Readers can simulate the installed
// kernel state while using the same coverage decision as live verification.
// Pair details are limited to the requested IPs and name; family counts retain
// registration evidence outside that selection for loose verification.
type domainRegistrySnapshot struct {
	names  map[string]domainNameSnapshot
	kernel map[netip.Addr]domainBitmaps
}

type domainNameSnapshot struct {
	families [2]int
	pairs    map[netip.Addr]domainPairSnapshot
}

type domainPairSnapshot struct {
	verification DomainVerification
	resident     bool
	retainUntil  time.Time
}

func domainFamily(ip netip.Addr) int {
	if ip.Is4() {
		return 0
	}
	return 1
}

// Snapshot is read-only: it neither refreshes retention nor retries projection.
func (g *DomainRegistry) Snapshot(ips []netip.Addr, name string) domainRegistrySnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	wanted := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		wanted[ip.Unmap()] = true
	}
	result := domainRegistrySnapshot{names: make(map[string]domainNameSnapshot, len(g.byName)), kernel: make(map[netip.Addr]domainBitmaps, len(wanted))}
	for domain, record := range g.byName {
		entry := domainNameSnapshot{}
		for ip, pair := range record.addresses {
			entry.families[domainFamily(ip)]++
			if !wanted[ip] && domain != name {
				continue
			}
			if entry.pairs == nil {
				entry.pairs = make(map[netip.Addr]domainPairSnapshot)
			}
			_, resident := g.kernel.resident[ip]
			entry.pairs[ip] = domainPairSnapshot{
				verification: g.verifyLocked(domain, ip), resident: resident, retainUntil: pair.retainUntil,
			}
		}
		result.names[domain] = entry
	}
	for ip := range wanted {
		if installed, resident := g.kernel.resident[ip]; resident {
			result.kernel[ip] = domainBitmaps{slices.Clone(installed.bump), slices.Clone(installed.routing)}
		}
	}
	return result
}
