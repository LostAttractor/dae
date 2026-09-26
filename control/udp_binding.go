// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func udpSourceKey(src netip.AddrPort) bpfUdpRoutingCacheKey {
	var key bpfUdpRoutingCacheKey
	key.Sip.U6Addr8 = src.Addr().As16()
	key.Sport = common.Htons(src.Port())
	return key
}

func deleteUDPRoutingTuples(m *ebpf.Map) error {
	var (
		key   bpfTuplesKey
		value bpfRoutingResult
		keys  []bpfTuplesKey
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if key.L4proto == unix.IPPROTO_UDP {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate routing tuples: %w", err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete UDP routing tuple: %w", err)
		}
	}
	return nil
}

func deleteUDPRoutingCache(m *ebpf.Map, preserveDirect bool) error {
	var (
		key   bpfUdpRoutingCacheKey
		value bpfUdpRoutingCacheValue
		keys  []bpfUdpRoutingCacheKey
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if !preserveDirect || value.Result.Outbound != 0 {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate UDP routing cache: %w", err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete UDP routing cache entry: %w", err)
		}
	}
	return nil
}

// The source lock serializes publication and removal of userspace bindings.
// Remove the initial kernel decision before releasing the binding: a packet
// cannot install the next lifetime's decision while this one still owns it.
func (c *ControlPlane) bindUDPSource(src netip.AddrPort, result *bpfRoutingResult) (func(), error) {
	key := udpSourceKey(src)
	bindings, decisions := c.core.bpf.UdpBindingsMap, c.core.bpf.UdpRoutingCacheMap
	if err := bindings.Update(&key, result.RouteEpoch, ebpf.UpdateNoExist); err != nil {
		return nil, fmt.Errorf("bind UDP source %v: %w", src, err)
	}
	return func() {
		for _, m := range []*ebpf.Map{decisions, bindings} {
			if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.WithFields(log.Fields{"source": src, "map": m.String()}).WithError(err).
					Warn("Failed to release UDP binding; stale source routing may remain")
			}
		}
	}, nil
}
