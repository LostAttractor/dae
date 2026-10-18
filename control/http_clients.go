// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/internal/routingabi"
)

// Readers take the lock only for one immutable-policy lookup. A writer holds
// it across persistence, the kernel-table swap and the final route commit.
// Never take routingState.rulesMu while holding this lock: route evaluation
// already holds rulesMu before consulting HTTP admission.
type httpClientAdmission struct {
	mu     sync.RWMutex
	policy *clientmatch.Policy
}

// Retain only the inner map template, not the full program collection.
var httpClientMapSpec = sync.OnceValues(func() (*ebpf.MapSpec, error) {
	spec, err := loadBPFSpec()
	if err != nil {
		return nil, err
	}
	return spec.Maps[bpfMapHttpClientsMap].InnerMap.Copy(), nil
})

func httpClientMap(policy *clientmatch.Policy) (*ebpf.Map, error) {
	template, err := httpClientMapSpec()
	if err != nil {
		return nil, err
	}
	spec := template.Copy()
	spec.Name = "http_clients"
	entries := policy.Entries()
	if uint64(len(entries)) > uint64(spec.MaxEntries) {
		return nil, fmt.Errorf("HTTP client policy exceeds %d entries", spec.MaxEntries)
	}
	table, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		key := bpfHttpClientKey{Prefixlen: routingabi.HTTP_CLIENT_KIND_BITS, Kind: routingabi.HTTP_CLIENT_ALL}
		switch {
		case entry.All:
		case entry.Prefix.IsValid():
			key.Kind = routingabi.HTTP_CLIENT_IPV6
			key.Address = entry.Prefix.Addr().As16()
			key.Prefixlen += uint32(entry.Prefix.Bits())
			if entry.Prefix.Addr().Is4() {
				key.Kind = routingabi.HTTP_CLIENT_IPV4
				key.Prefixlen += routingabi.HTTP_CLIENT_MAPPED_PREFIX_BITS
			}
		default:
			key.Kind = routingabi.HTTP_CLIENT_MAC
			if entry.Override {
				key.Kind = routingabi.HTTP_CLIENT_MAC_OVERRIDE
			}
			key.Prefixlen += routingabi.HTTP_CLIENT_MAC_BITS
			copy(key.Address[:], entry.MAC[:])
		}
		value := bpfHttpClientDecision{Order: entry.Decision.Order}
		if entry.Decision.Allow {
			value.Allow = 1
		}
		if err := table.Update(key, value, ebpf.UpdateAny); err != nil {
			table.Close()
			return nil, err
		}
	}
	if err := table.Freeze(); err != nil {
		table.Close()
		return nil, err
	}
	return table, nil
}

func (c *ControlPlane) httpClientAllowed(ip netip.Addr, mac [6]byte) bool {
	enabled, _ := c.mitmSelection(ip, mac)
	return enabled
}

func (c *ControlPlane) restoreHTTPClients() error {
	policy := c.mitmClients.Compile(c.settings.MITMOverrides())
	if c.kernelReady {
		table, err := httpClientMap(policy)
		if err != nil {
			return fmt.Errorf("prepare HTTP client policy: %w", err)
		}
		defer table.Close()
		if err := c.core.bpf.HttpClientsMap.Update(uint32(0), table, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("publish HTTP client policy: %w", err)
		}
	}
	c.httpClients.mu.Lock()
	c.httpClients.policy = policy
	c.httpClients.mu.Unlock()
	if c.routingMatcher != nil {
		c.routingMatcher.httpClientAllowed = c.httpClientAllowed
	}
	return nil
}

func (c *ControlPlane) publishHTTPClients() error {
	c.httpClients.mu.RLock()
	defer c.httpClients.mu.RUnlock()
	table, err := httpClientMap(c.httpClients.policy)
	if err != nil {
		return fmt.Errorf("prepare HTTP client policy: %w", err)
	}
	defer table.Close()
	if err := c.core.bpf.HttpClientsMap.Update(uint32(0), table, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("publish HTTP client policy: %w", err)
	}
	return nil
}

func (c *ControlPlane) changeHTTPClients(previous, next settings.Snapshot, persist, commit func() error) error {
	if maps.Equal(previous.MITM, next.MITM) {
		if err := persist(); err != nil {
			return err
		}
		return commit()
	}
	policy := c.mitmClients.Compile(next.MITMOverrides())
	var table, oldTable *ebpf.Map
	if c.kernelReady {
		var err error
		table, err = httpClientMap(policy)
		if err != nil {
			return fmt.Errorf("prepare HTTP client policy: %w", err)
		}
		defer table.Close()
		if err := c.core.bpf.HttpClientsMap.Lookup(uint32(0), &oldTable); err != nil {
			return fmt.Errorf("retain HTTP client policy: %w", err)
		}
		defer oldTable.Close()
	}
	c.httpClients.mu.Lock()
	defer c.httpClients.mu.Unlock()
	if err := persist(); err != nil {
		return err
	}
	if table != nil {
		if err := c.core.bpf.HttpClientsMap.Update(uint32(0), table, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("publish HTTP client policy: %w", err)
		}
	}
	if err := commit(); err != nil {
		if oldTable != nil {
			if rollback := c.core.bpf.HttpClientsMap.Update(uint32(0), oldTable, ebpf.UpdateAny); rollback != nil {
				// The new policy is still visible in the kernel; keep userspace truthful.
				c.httpClients.policy = policy
				return errors.Join(err, fmt.Errorf("restore HTTP client policy: %w", rollback))
			}
		}
		return err
	}
	c.httpClients.policy = policy
	return nil
}
