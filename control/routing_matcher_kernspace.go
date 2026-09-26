/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

type _bpfLpmKey struct {
	PrefixLen uint32
	Data      [4]uint32
}

func (o *bpfObjects) newLpmMap(prefixes []netip.Prefix) (m *ebpf.Map, err error) {
	m, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		Flags:      o.UnusedLpmType.Flags(),
		MaxEntries: o.UnusedLpmType.MaxEntries(),
		KeySize:    o.UnusedLpmType.KeySize(),
		ValueSize:  o.UnusedLpmType.ValueSize(),
	})
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return m, nil
	}
	keys := make([]_bpfLpmKey, len(prefixes))
	values := make([]uint32, len(prefixes))
	for i, prefix := range prefixes {
		keys[i], values[i] = cidrToBpfLpmKey(prefix), 1
	}
	if _, err = m.BatchUpdate(keys, values, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

func cidrToBpfLpmKey(prefix netip.Prefix) _bpfLpmKey {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += 96
	}
	ip := prefix.Addr().As16()
	return _bpfLpmKey{
		PrefixLen: uint32(bits),
		Data:      common.Ipv6ByteSliceToUint32Array(ip[:]),
	}
}

func encodeRoutingProfiles(profiles []routingProfile) (ids []uint32, values []bpfRoutingProfile) {
	ids = make([]uint32, len(profiles))
	values = make([]bpfRoutingProfile, len(profiles))
	for i, profile := range profiles {
		ids[i] = profile.ID
		value := &values[i]
		for _, span := range profile.Spans {
			for matchIndex := span.Start; matchIndex < span.End; matchIndex++ {
				value.Steps[value.Length] = uint16(matchIndex)
				value.Length++
			}
		}
	}
	return ids, values
}

func (b *RoutingMatcherBuilder) BuildKernspace() error {
	// Retire and drain callbacks from the previous routing generation before
	// writing new map contents, otherwise an in-flight callback could restore
	// an old rule or profile binding after the upload.
	b.bpf.clearRoutingRegistrations()
	if err := b.uploadLPMTries(); err != nil {
		return err
	}
	if err := b.uploadRoutingPool(); err != nil {
		return err
	}
	if err := b.uploadRoutingProfiles(); err != nil {
		return err
	}
	if err := b.activateInterfaceRulePatches(); err != nil {
		return fmt.Errorf("initialize interface routing rules: %w", err)
	}
	if err := b.activateProfileBindings(); err != nil {
		return fmt.Errorf("initialize interface routing profiles: %w", err)
	}
	if err := b.bpf.DefaultRoutingProfile.Set(b.defaultProfileID); err != nil {
		return fmt.Errorf("select default routing policy: %w", err)
	}
	b.bpf.activeLpmTrieCount = uint32(b.kernelLpmLen)
	if b.profileIDPlan != nil {
		b.bpf.routingProfileIDs = *b.profileIDPlan
	}
	return nil
}

func (b *RoutingMatcherBuilder) uploadLPMTries() error {
	if err := b.forEachStaleLpmSlot(func(i uint32) error {
		return b.bpf.LpmArrayMap.Update(i, b.bpf.UnusedLpmType, ebpf.UpdateAny)
	}); err != nil {
		return err
	}
	for i, cidrs := range b.simulatedLpmTries[:b.kernelLpmLen] {
		m, err := b.bpf.newLpmMap(cidrs)
		if err != nil {
			return fmt.Errorf("create LPM map %d: %w", i, err)
		}
		if err := b.bpf.LpmArrayMap.Update(uint32(i), m, ebpf.UpdateAny); err != nil {
			m.Close()
			return fmt.Errorf("update LPM map slot %d: %w", i, err)
		}
		m.Close()
	}
	return nil
}

func (b *RoutingMatcherBuilder) uploadRoutingPool() error {
	keys := common.ARangeU32(uint32(b.routing.end))
	if _, err := b.bpf.RoutingMap.BatchUpdate(keys, b.rules[:b.routing.end], &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("batch update routing map: %w", err)
	}
	log.Infof("Routing match set len: %v/%v", b.routing.end, consts.MaxMatchSetLen)
	return nil
}

func (b *RoutingMatcherBuilder) uploadRoutingProfiles() error {
	if err := pruneRoutingHashMap(b.bpf.RoutingInterfaceMap, nil); err != nil {
		return fmt.Errorf("clear routing interface profiles: %w", err)
	}
	ids, values := encodeRoutingProfiles(b.profiles)
	liveIDs := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		liveIDs[id] = struct{}{}
	}
	// Retire obsolete IDs before uploading: a full old generation must not
	// prevent a new generation from fitting in this bounded hash map. Keep
	// surviving IDs (including default) present until atomically replaced.
	if err := pruneRoutingHashMap(b.bpf.RoutingProfileMap, liveIDs); err != nil {
		return fmt.Errorf("remove stale routing profiles: %w", err)
	}
	options := &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}
	if _, err := b.bpf.RoutingProfileMap.BatchUpdate(ids, values, options); err != nil {
		return fmt.Errorf("batch update routing profiles: %w", err)
	}
	return nil
}

// Routing callbacks have been drained before activation. Iterate keys only:
// profile values contain the full execution sequence and need not be copied.
func pruneRoutingHashMap(m *ebpf.Map, keep map[uint32]struct{}) error {
	var previous any
	var stale []uint32
	for {
		var key uint32
		if err := m.NextKey(previous, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return err
		}
		if _, retained := keep[key]; !retained {
			stale = append(stale, key)
		}
		previous = key
	}
	for _, key := range stale {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func (b *RoutingMatcherBuilder) forEachStaleLpmSlot(fn func(uint32) error) error {
	for i := uint32(b.kernelLpmLen); i < b.bpf.activeLpmTrieCount; i++ {
		if err := fn(i); err != nil {
			return fmt.Errorf("process stale LPM slot at index %d: %w", i, err)
		}
	}
	return nil
}
