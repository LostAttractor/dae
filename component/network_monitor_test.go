/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func testLookupRule(table int) netlink.Rule {
	rule := netlink.NewRule()
	rule.Table = table
	return *rule
}

func TestBuildHostNetworkSnapshotTracksWlanReadiness(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Index:     2,
		Name:      "wlan0",
		Flags:     net.FlagUp,
		OperState: netlink.OperDormant,
	}}
	data := hostNetworkData{
		links: []netlink.Link{link},
		routes4: []netlink.Route{{
			LinkIndex: 2,
			Table:     unix.RT_TABLE_MAIN,
			Type:      unix.RTN_UNICAST,
			Gw:        net.ParseIP("192.0.2.1"),
		}},
		rules4: []netlink.Rule{testLookupRule(unix.RT_TABLE_MAIN)},
		addrs4: map[int][]netlink.Addr{
			2: {{IPNet: &net.IPNet{IP: net.ParseIP("192.0.2.2"), Mask: net.CIDRMask(24, 32)}}},
		},
		addrs6: map[int][]netlink.Addr{},
	}

	dormant := buildHostNetworkSnapshot(data)
	if dormant.Ready() || len(dormant.Interfaces) != 1 || !dormant.Interfaces[0].IPv4Default {
		t.Fatalf("dormant snapshot = %+v", dormant)
	}

	link.LinkAttrs.OperState = netlink.OperUp
	link.LinkAttrs.RawFlags = unix.IFF_LOWER_UP
	connected := buildHostNetworkSnapshot(data)
	if !connected.Ready() || connected.Interfaces[0].IPv4Source == "" {
		t.Fatalf("connected snapshot = %+v", connected)
	}
	if !connected.ConnectivityChanged(dormant) {
		t.Fatal("dormant to connected transition did not change connectivity")
	}
}

func TestBuildHostNetworkSnapshotWaitsForIPv6DAD(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Index:     3,
		Name:      "wlan0",
		Flags:     net.FlagUp,
		RawFlags:  unix.IFF_LOWER_UP,
		OperState: netlink.OperUp,
	}}
	addr := netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_TENTATIVE,
	}
	data := hostNetworkData{
		links: []netlink.Link{link},
		routes6: []netlink.Route{{
			LinkIndex: 3,
			Table:     unix.RT_TABLE_MAIN,
			Type:      unix.RTN_UNICAST,
		}},
		rules6: []netlink.Rule{testLookupRule(unix.RT_TABLE_MAIN)},
		addrs4: map[int][]netlink.Addr{},
		addrs6: map[int][]netlink.Addr{3: {addr}},
	}

	if snapshot := buildHostNetworkSnapshot(data); snapshot.Ready() {
		t.Fatalf("tentative IPv6 address was considered ready: %+v", snapshot)
	}
	data.addrs6[3][0].Flags = 0
	if snapshot := buildHostNetworkSnapshot(data); snapshot.Interfaces[0].IPv6Source == "" {
		t.Fatalf("completed IPv6 DAD was not considered ready: %+v", snapshot)
	}
}

func TestBuildHostNetworkSnapshotIncludesReachableCustomRouteTables(t *testing.T) {
	data := hostNetworkData{
		links: []netlink.Link{
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 4, Name: "wg0"}},
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 5, Name: "staging0"}},
		},
		routes4: []netlink.Route{
			{LinkIndex: 4, Table: 100, Type: unix.RTN_UNICAST},
			{LinkIndex: 5, Table: 101, Type: unix.RTN_UNICAST},
		},
		rules4: []netlink.Rule{testLookupRule(100)},
		addrs4: map[int][]netlink.Addr{},
		addrs6: map[int][]netlink.Addr{},
	}
	snapshot := buildHostNetworkSnapshot(data)
	if len(snapshot.Interfaces) != 1 || snapshot.Interfaces[0].Name != "wg0" || !snapshot.Interfaces[0].IPv4Default {
		t.Fatalf("custom-table snapshot = %+v", snapshot)
	}
}

func TestBuildHostNetworkSnapshotTracksMultipathRecovery(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Index: 5, Name: "eth0", Flags: net.FlagUp, OperState: netlink.OperUp,
	}}
	nextHop := &netlink.NexthopInfo{LinkIndex: 5, Flags: unix.RTNH_F_LINKDOWN}
	data := hostNetworkData{
		links: []netlink.Link{link},
		routes4: []netlink.Route{{
			Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, MultiPath: []*netlink.NexthopInfo{nextHop},
		}},
		rules4: []netlink.Rule{testLookupRule(unix.RT_TABLE_MAIN)},
		addrs4: map[int][]netlink.Addr{
			5: {{IPNet: &net.IPNet{IP: net.ParseIP("192.0.2.2"), Mask: net.CIDRMask(24, 32)}}},
		},
		addrs6: map[int][]netlink.Addr{},
	}

	down := buildHostNetworkSnapshot(data)
	if down.Ready() || len(down.Interfaces) != 0 {
		t.Fatalf("link-down multipath snapshot = %+v", down)
	}
	nextHop.Flags = 0
	up := buildHostNetworkSnapshot(data)
	if !up.Ready() || len(up.Interfaces) != 1 {
		t.Fatalf("recovered multipath snapshot = %+v", up)
	}
	if !up.ConnectivityChanged(down) {
		t.Fatal("multipath recovery did not change connectivity")
	}
}

func TestBuildHostNetworkSnapshotExcludesPrefixSuppressedDefault(t *testing.T) {
	rule := testLookupRule(100)
	rule.SuppressPrefixlen = 0
	data := hostNetworkData{
		links:   []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 4, Name: "wg0"}}},
		routes4: []netlink.Route{{LinkIndex: 4, Table: 100, Type: unix.RTN_UNICAST}},
		rules4:  []netlink.Rule{rule},
		addrs4:  map[int][]netlink.Addr{},
		addrs6:  map[int][]netlink.Addr{},
	}

	if snapshot := buildHostNetworkSnapshot(data); len(snapshot.Interfaces) != 0 || snapshot.IPv4RouteFingerprint != "" {
		t.Fatalf("prefix-suppressed default route remained reachable: %+v", snapshot)
	}
}

func TestBuildHostNetworkSnapshotExcludesSuppressedInterfaceGroup(t *testing.T) {
	rule := testLookupRule(100)
	rule.SuppressIfgroup = 10
	data := hostNetworkData{
		links: []netlink.Link{
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 4, Name: "suppressed0", Group: 10}},
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 5, Name: "reachable0", Group: 20}},
		},
		routes4: []netlink.Route{
			{LinkIndex: 4, Table: 100, Type: unix.RTN_UNICAST},
			{LinkIndex: 5, Table: 100, Type: unix.RTN_UNICAST},
		},
		rules4: []netlink.Rule{rule},
		addrs4: map[int][]netlink.Addr{},
		addrs6: map[int][]netlink.Addr{},
	}

	snapshot := buildHostNetworkSnapshot(data)
	if len(snapshot.Interfaces) != 1 || snapshot.Interfaces[0].Name != "reachable0" {
		t.Fatalf("interface-group-suppressed snapshot = %+v", snapshot)
	}

	data.rules4 = append(data.rules4, testLookupRule(100))
	snapshot = buildHostNetworkSnapshot(data)
	if len(snapshot.Interfaces) != 2 {
		t.Fatalf("unsuppressed lookup rule did not restore both paths: %+v", snapshot)
	}
}

func TestBuildHostNetworkSnapshotFingerprintsRules(t *testing.T) {
	rule := netlink.NewRule()
	rule.Table = unix.RT_TABLE_MAIN
	rule.Priority = 100
	data := hostNetworkData{rules4: []netlink.Rule{*rule}}
	initial := buildHostNetworkSnapshot(data)

	data.rules4[0].Mark = 1
	changed := buildHostNetworkSnapshot(data)
	if initial.IPv4RuleFingerprint == changed.IPv4RuleFingerprint || initial.Equal(changed) {
		t.Fatal("RPDB rule change did not change the host network fingerprint")
	}
}

func TestHostNetworkMonitorSnapshotDoesNotWaitForInitialization(t *testing.T) {
	release := make(chan struct{})
	want := HostNetworkSnapshot{
		Interfaces: []DefaultRouteInterface{{Index: 2, Name: "eth0", IPv4Default: true}},
	}
	m := newHostNetworkMonitor(func() (HostNetworkSnapshot, error) {
		<-release
		return want, nil
	}, nil, nil, nil, nil, nil, nil, time.Millisecond, time.Hour)
	t.Cleanup(func() { _ = m.Close() })

	if got := m.Snapshot(); got.Revision() != 0 {
		t.Fatalf("snapshot revision before initialization = %d", got.Revision())
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		got := m.Snapshot()
		if got.Revision() != 0 {
			if !got.Equal(want) {
				t.Fatalf("initial snapshot = %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("monitor did not initialize")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHostNetworkMonitorRetriesInitialFailure(t *testing.T) {
	var attempts atomic.Int32
	m := newHostNetworkMonitor(func() (HostNetworkSnapshot, error) {
		if attempts.Add(1) == 1 {
			return HostNetworkSnapshot{}, errors.New("temporary dump failure")
		}
		return HostNetworkSnapshot{}, nil
	}, nil, nil, nil, nil, nil, nil, time.Millisecond, time.Hour)
	t.Cleanup(func() { _ = m.Close() })

	if got := m.Snapshot(); got.Revision() != 0 {
		t.Fatalf("snapshot revision after failed initialization = %d", got.Revision())
	}
	deadline := time.Now().Add(time.Second)
	for m.Snapshot().Revision() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := m.Snapshot(); attempts.Load() < 2 || got.Revision() == 0 {
		t.Fatalf("attempts = %d, revision = %d", attempts.Load(), got.Revision())
	}
}

func TestHostNetworkMonitorClosesDuringInitialFailure(t *testing.T) {
	called := make(chan struct{}, 1)
	m := newHostNetworkMonitor(func() (HostNetworkSnapshot, error) {
		select {
		case called <- struct{}{}:
		default:
		}
		return HostNetworkSnapshot{}, errors.New("persistent dump failure")
	}, nil, nil, nil, nil, nil, nil, time.Millisecond, time.Hour)
	<-called
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked while initial reconciliation was failing")
	}
}

func TestHostNetworkMonitorDebouncesAndPublishesChanges(t *testing.T) {
	var mu sync.RWMutex
	current := HostNetworkSnapshot{
		Interfaces: []DefaultRouteInterface{{Index: 2, Name: "wlan0", IPv4Default: true}},
	}
	snapshotFn := func() (HostNetworkSnapshot, error) {
		mu.RLock()
		defer mu.RUnlock()
		return current, nil
	}
	linkCh := make(chan netlink.LinkUpdate, 4)
	addrCh := make(chan netlink.AddrUpdate, 4)
	routeCh := make(chan netlink.RouteUpdate, 4)
	ruleCh := make(chan struct{}, 4)
	subscriptionEnd := make(chan struct{})
	go func() {
		<-subscriptionEnd
		close(linkCh)
		close(addrCh)
		close(routeCh)
		close(ruleCh)
	}()
	m := newHostNetworkMonitor(snapshotFn, linkCh, addrCh, routeCh, ruleCh, subscriptionEnd, nil, 5*time.Millisecond, time.Hour)

	deadline := time.Now().Add(time.Second)
	for m.Snapshot().Revision() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	initial := m.Snapshot()
	changes := make(chan HostNetworkSnapshot, 1)
	m.Register(func(_, next HostNetworkSnapshot) { changes <- next })

	mu.Lock()
	current.Interfaces[0].IPv4Source = "192.0.2.2"
	mu.Unlock()
	linkCh <- netlink.LinkUpdate{}
	addrCh <- netlink.AddrUpdate{}
	routeCh <- netlink.RouteUpdate{}
	ruleCh <- struct{}{}

	select {
	case next := <-changes:
		if !next.Ready() {
			t.Fatalf("published snapshot is not ready: %+v", next)
		}
		if next.Revision() <= initial.Revision() {
			t.Fatalf("snapshot revision = %d, initial revision = %d", next.Revision(), initial.Revision())
		}
	case <-time.After(time.Second):
		t.Fatal("network change was not published")
	}
	select {
	case <-changes:
		t.Fatal("debounced event burst published more than once")
	case <-time.After(20 * time.Millisecond):
	}

	mu.Lock()
	current.IPv4RuleFingerprint = "changed-rule"
	mu.Unlock()
	ruleCh <- struct{}{}
	select {
	case next := <-changes:
		if next.IPv4RuleFingerprint != "changed-rule" {
			t.Fatalf("published rule fingerprint = %q", next.IPv4RuleFingerprint)
		}
	case <-time.After(time.Second):
		t.Fatal("rule change was not published")
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-subscriptionEnd:
	default:
		t.Fatal("monitor did not stop its subscriptions")
	}
}

func TestHostNetworkMonitorResubscribesAfterChannelClosure(t *testing.T) {
	first := make(chan netlink.LinkUpdate)
	close(first)
	replacement := make(chan netlink.LinkUpdate, 1)
	subscriptionEnd := make(chan struct{})
	subscribed := make(chan struct{}, 1)
	subscriptions := &hostNetworkSubscriptions{
		link: func(done <-chan struct{}) (<-chan netlink.LinkUpdate, error) {
			subscribed <- struct{}{}
			go func() {
				<-done
				close(replacement)
			}()
			return replacement, nil
		},
	}
	var mu sync.RWMutex
	current := HostNetworkSnapshot{Interfaces: []DefaultRouteInterface{{
		Index: 2, Name: "eth0", IPv4Default: true,
	}}}
	snapshotFn := func() (HostNetworkSnapshot, error) {
		mu.RLock()
		defer mu.RUnlock()
		return current, nil
	}
	m := newHostNetworkMonitor(snapshotFn, first, nil, nil, nil, subscriptionEnd, subscriptions,
		5*time.Millisecond, time.Hour)
	t.Cleanup(func() { _ = m.Close() })
	changes := make(chan HostNetworkSnapshot, 2)
	m.Register(func(_, next HostNetworkSnapshot) { changes <- next })

	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("link subscription was not restored")
	}
	mu.Lock()
	current.Interfaces[0].IPv4Source = "192.0.2.2"
	mu.Unlock()
	replacement <- netlink.LinkUpdate{}

	deadline := time.After(time.Second)
	for {
		select {
		case snapshot := <-changes:
			if snapshot.Interfaces[0].IPv4Source == "192.0.2.2" {
				return
			}
		case <-deadline:
			t.Fatal("restored subscription did not publish an update")
		}
	}
}
