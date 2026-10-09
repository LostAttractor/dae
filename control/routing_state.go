// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/pkg/trie"
)

// routingState owns the compiled routing tables and their dynamic bindings.
// Matchers and interface callbacks retain this state, not the compiler.
type routingState struct {
	bpf               *BPFState
	rules             []bpfMatchSet
	rulesMu           sync.RWMutex
	simulatedLpmTries [][]netip.Prefix
	clientSetSlots    map[string]int
	kernelLpmLen      int
	routing           RoutingProgram
}

func (s *routingState) ClientSets() []string {
	if s == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(s.clientSetSlots))
}

// SetClientMembers prepares both replacements before publishing either one.
// The caller serializes business updates and owns persistence/exports.
func (s *routingState) SetClientMembers(matcher *RoutingMatcher, name string, members [][6]byte, kernelReady bool) error {
	if s == nil {
		return nil
	}
	slot, exists := s.clientSetSlots[name]
	if !exists {
		return nil
	}
	prefixes := sourceMacPrefixes(members)
	s.rulesMu.RLock()
	unchanged := slices.Equal(s.simulatedLpmTries[slot], prefixes)
	s.rulesMu.RUnlock()
	if unchanged {
		return nil
	}
	next, err := trie.NewTrieFromPrefixes(prefixes)
	if err != nil {
		return fmt.Errorf("build client set %q: %w", name, err)
	}
	var kernelMap *ebpf.Map
	if kernelReady && slot < s.kernelLpmLen {
		kernelMap, err = s.bpf.newLpmMap(prefixes)
		if err != nil {
			return fmt.Errorf("build kernel client set %q: %w", name, err)
		}
		defer kernelMap.Close()
	}
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	if kernelMap != nil {
		if err := s.bpf.LpmArrayMap.Update(uint32(slot), kernelMap, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update kernel client set %q: %w", name, err)
		}
	}
	s.simulatedLpmTries[slot] = prefixes
	matcher.lpmMatcher[slot] = next
	return nil
}

func (s *routingState) updateIfindex(index int, ifindex uint32, active bool) error {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	current := s.rules[index]
	binary.LittleEndian.PutUint32(current.Value[:], ifindex)
	if active && index < s.routing.end {
		if err := s.bpf.RoutingMap.Update(uint32(index), current, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	s.rules[index] = current
	return nil
}
