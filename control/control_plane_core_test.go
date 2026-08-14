/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"slices"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestControlPlaneCoreCleanupOwnership(t *testing.T) {
	core := &controlPlaneCore{}
	var cleaned []string
	record := func(name string) func() error {
		return func() error {
			cleaned = append(cleaned, name)
			return nil
		}
	}

	core.addCleanup(record("static-first"))
	core.addCleanup(record("static-last"))
	owned := hostTCXLink{linkIndex: 1, role: hostTCXLanIngress, close: record("owned-link")}
	if !core.ownHostTCXLink(owned) {
		t.Fatal("first ownership registration was rejected")
	}
	if core.ownHostTCXLink(hostTCXLink{linkIndex: 1, role: hostTCXLanIngress, close: record("duplicate-link")}) {
		t.Fatal("duplicate ownership registration was accepted")
	}
	released := hostTCXLink{linkIndex: 2, role: hostTCXWanIngress, close: record("released-link")}
	core.ownHostTCXLink(released)
	if err := core.closeHostTCXLinks(released.linkIndex); err != nil {
		t.Fatal(err)
	}
	released.close = record("recreated-link")
	core.ownHostTCXLink(released)

	for _, cleanup := range core.takeCleanups() {
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"released-link", "recreated-link", "owned-link", "static-last", "static-first"}
	if !slices.Equal(cleaned, want) {
		t.Fatalf("cleanup order = %v, want %v", cleaned, want)
	}
	if cleanups := core.takeCleanups(); len(cleanups) != 0 {
		t.Fatalf("cleanup ownership was not drained: %d entries", len(cleanups))
	}
}

func TestControlPlaneCoreCleanupRegistrationConcurrent(t *testing.T) {
	core := &controlPlaneCore{}
	var workers sync.WaitGroup
	for i := 0; i < 100; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			core.addCleanup(func() error { return nil })
			core.ownHostTCXLink(hostTCXLink{linkIndex: i, close: func() error { return nil }})
		}(i)
	}
	workers.Wait()
	if cleanups := core.takeCleanups(); len(cleanups) != 200 {
		t.Fatalf("cleanup count = %d, want 200", len(cleanups))
	}
}

func TestLegacyTCFilter(t *testing.T) {
	newFilter := func(priority, minor uint16, name string) *netlink.BpfFilter {
		return &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				Handle:   netlink.MakeHandle(0x2023, minor),
				Priority: priority,
				Protocol: unix.ETH_P_ALL,
			},
			Name:         name,
			DirectAction: true,
		}
	}
	originalIngress := newFilter(0, 1, consts.AppName+"_ingress")
	originalIngress.FilterAttrs.Handle = netlink.MakeHandle(0, 1)
	tests := []struct {
		name   string
		filter *netlink.BpfFilter
		parent uint32
		want   bool
	}{
		{"current LAN ingress", newFilter(2, 4, consts.AppName+"_lan_ingress_l2"), netlink.HANDLE_MIN_INGRESS, true},
		{"historical WAN egress", newFilter(1, 1, consts.AppName+"_wan_egress"), netlink.HANDLE_MIN_EGRESS, true},
		{"original ingress", originalIngress, netlink.HANDLE_MIN_INGRESS, true},
		{"foreign name", newFilter(1, 2, "foreign_wan_ingress"), netlink.HANDLE_MIN_INGRESS, false},
		{"wrong parent", newFilter(1, 2, consts.AppName+"_wan_ingress"), netlink.HANDLE_MIN_EGRESS, false},
		{"unknown handle", newFilter(1, 6, consts.AppName+"_wan_ingress"), netlink.HANDLE_MIN_INGRESS, false},
	}
	for _, test := range tests {
		if got := legacyTCFilter(test.filter, test.parent); got != test.want {
			t.Errorf("%s: legacyTCFilter() = %v, want %v", test.name, got, test.want)
		}
	}
}
