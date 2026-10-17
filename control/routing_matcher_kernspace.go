/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
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

func (m *RoutingMatcher) BuildKernspace() error {
	// Each configuration uploads once into fresh private maps. Mutable client
	// sets and interface bindings update their own slots after preparation.
	if err := m.uploadLPMTries(); err != nil {
		return err
	}
	if err := m.uploadRoutingPool(); err != nil {
		return err
	}
	if err := m.uploadRoutingProfiles(); err != nil {
		return err
	}
	if err := m.activateInterfaceRulePatches(); err != nil {
		return fmt.Errorf("initialize interface routing rules: %w", err)
	}
	if err := m.activateProfileBindings(); err != nil {
		return fmt.Errorf("initialize interface routing profiles: %w", err)
	}
	if err := m.bpf.DefaultRoutingProfile.Set(m.defaultProfileID); err != nil {
		return fmt.Errorf("select default routing policy: %w", err)
	}
	return nil
}

func (m *RoutingMatcher) uploadLPMTries() error {
	for i, cidrs := range m.simulatedLpmTries[:m.kernelLpmLen] {
		kernelMap, err := m.bpf.newLpmMap(cidrs)
		if err != nil {
			return fmt.Errorf("create LPM map %d: %w", i, err)
		}
		if err := m.bpf.LpmArrayMap.Update(uint32(i), kernelMap, ebpf.UpdateAny); err != nil {
			kernelMap.Close()
			return fmt.Errorf("update LPM map slot %d: %w", i, err)
		}
		kernelMap.Close()
	}
	return nil
}

func (m *RoutingMatcher) uploadRoutingPool() error {
	keys := common.ARangeU32(uint32(m.routing.end))
	if _, err := m.bpf.RoutingMap.BatchUpdate(keys, m.matches[:m.routing.end], &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("batch update routing map: %w", err)
	}
	log.Infof("Routing match set len: %v/%v", m.routing.end, consts.MaxMatchSetLen)
	return nil
}

func (m *RoutingMatcher) uploadRoutingProfiles() error {
	ids, values := encodeRoutingProfiles(m.profileInfo)
	options := &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}
	if _, err := m.bpf.RoutingProfileMap.BatchUpdate(ids, values, options); err != nil {
		return fmt.Errorf("batch update routing profiles: %w", err)
	}
	return nil
}
