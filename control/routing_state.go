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

// routingState owns live instruction bindings and client tries. Each matcher
// gets its own state; compilation and diagnostic snapshots never share mutations.
type routingState struct {
	bpf               *BPFState
	matches           []bpfMatchSet
	lpmMatcher        []*trie.Trie
	rulesMu           sync.RWMutex
	simulatedLpmTries [][]netip.Prefix
	clientSetSlots    map[string]int
	kernelLpmLen      int
	routing           RoutingProgram
}

// Reuse only immutable predicates at matching slots. Client membership can
// change while a successor is being prepared, and belongs to each generation.
func (s *routingState) reuseStaticTries(dst []*trie.Trie, prefixes [][]netip.Prefix, clients map[string]int) {
	dynamic := make(map[int]bool, len(clients)+len(s.clientSetSlots))
	for _, slot := range clients {
		dynamic[slot] = true
	}
	for _, slot := range s.clientSetSlots {
		dynamic[slot] = true
	}
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	for i := range min(len(dst), len(s.lpmMatcher)) {
		if !dynamic[i] && slices.Equal(prefixes[i], s.simulatedLpmTries[i]) {
			dst[i] = s.lpmMatcher[i]
		}
	}
}

func (s *routingState) ClientSets() []string {
	if s == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(s.clientSetSlots))
}

// SetClientMembers prepares both replacements before publishing either one.
// The caller serializes business updates and owns persistence/exports.
func (s *routingState) SetClientMembers(name string, members [][6]byte, kernelReady bool) error {
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
	s.lpmMatcher[slot] = next
	return nil
}

func (s *routingState) updateIfindex(index int, ifindex uint32, active bool) error {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	current := s.matches[index]
	binary.LittleEndian.PutUint32(current.Value[:], ifindex)
	if active && index < s.routing.end {
		if err := s.bpf.RoutingMap.Update(uint32(index), current, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	s.matches[index] = current
	return nil
}

// snapshot copies only evaluation state, without kernel handles or writers.
// Published tries are immutable and can be shared until a membership replacement.
func (s *routingState) snapshot() *routingState {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	return &routingState{matches: slices.Clone(s.matches), lpmMatcher: slices.Clone(s.lpmMatcher)}
}
