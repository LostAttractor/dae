/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type routingInterfaceRulePatch struct {
	ifname     string
	matchIndex int
}

func (b *RoutingMatcherBuilder) activateInterfaceRulePatches() error {
	for _, patch := range b.interfaceRulePatches {
		if b.ifmgr == nil {
			return fmt.Errorf("interface manager is required for routing rule interface %q", patch.ifname)
		}
		update := func(ifindex uint32) error { return b.updateIfindex(patch.matchIndex, ifindex, true) }
		cancel, err := b.ifmgr.RegisterSyncCancelable(patch.ifname,
			func(link netlink.Link) error { return update(uint32(link.Attrs().Index)) },
			func(link netlink.Link) {
				log.Warnf("New link creation of '%v' is detected. Re-fetching ifindex for it.", link.Attrs().Name)
				if err := update(uint32(link.Attrs().Index)); err != nil {
					log.Errorf("Update failed: %v", err)
				}
			},
			func(link netlink.Link) {
				log.Warnf("Link deletion of '%v' is detected. Re-fetching ifindex once it is re-created.", link.Attrs().Name)
				if err := update(0); err != nil {
					log.Errorf("Update failed: %v", err)
				}
			},
		)
		if err != nil {
			return fmt.Errorf("register interface %q: %w", patch.ifname, err)
		}
		b.bpf.routingRegistrationCancels = append(b.bpf.routingRegistrationCancels, cancel)
	}
	return nil
}

func (b *RoutingMatcherBuilder) activateProfileBindings() error {
	ifmgr := b.ifmgr
	routingInterfaceMap := b.bpf.RoutingInterfaceMap
	for _, profile := range b.profiles {
		for _, ifname := range profile.InterfaceNames {
			if ifmgr == nil {
				return fmt.Errorf("interface manager is required for routing profiles")
			}
			update := func(link netlink.Link) error {
				ifindex := uint32(link.Attrs().Index)
				if err := routingInterfaceMap.Update(ifindex, profile.ID, ebpf.UpdateAny); err != nil {
					return fmt.Errorf("map interface %q to routing profile %d: %w", ifname, profile.ID, err)
				}
				return nil
			}
			remove := func(link netlink.Link) {
				ifindex := uint32(link.Attrs().Index)
				if err := routingInterfaceMap.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					log.Errorf("Delete routing profile for interface %q failed: %v", ifname, err)
				}
			}
			cancel, err := ifmgr.RegisterSyncCancelable(ifname, update, func(link netlink.Link) {
				if err := update(link); err != nil {
					log.Errorf("Update routing profile for interface %q failed: %v", ifname, err)
				}
			}, remove)
			if err != nil {
				return err
			}
			b.bpf.routingRegistrationCancels = append(b.bpf.routingRegistrationCancels, cancel)
		}
	}
	return nil
}
