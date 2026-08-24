/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	hostNetworkDebounceInterval = 200 * time.Millisecond
	hostNetworkRetryInterval    = 500 * time.Millisecond
	hostNetworkResyncInterval   = time.Minute
)

// DefaultRouteInterface describes one interface participating in a unicast
// default route. Readiness additionally requires an operational link and a
// usable address for the route's family.
type DefaultRouteInterface struct {
	Index       int
	Name        string
	IPv4Default bool
	IPv6Default bool
	IPv4Source  string
	IPv6Source  string
}

// HostNetworkSnapshot is an authoritative view rebuilt after netlink events.
// Route fingerprints include gateways and metrics so path changes on the same
// interface still wake connectivity checks.
type HostNetworkSnapshot struct {
	Interfaces           []DefaultRouteInterface
	IPv4RouteFingerprint string
	IPv6RouteFingerprint string
	IPv4RuleFingerprint  string
	IPv6RuleFingerprint  string
	revision             uint64
}

// Revision increases whenever the monitor publishes a different snapshot.
func (s HostNetworkSnapshot) Revision() uint64 { return s.revision }

func (s HostNetworkSnapshot) Ready() bool {
	for _, intf := range s.Interfaces {
		if intf.IPv4Source != "" || intf.IPv6Source != "" {
			return true
		}
	}
	return false
}

func (s HostNetworkSnapshot) Equal(other HostNetworkSnapshot) bool {
	return s.IPv4RouteFingerprint == other.IPv4RouteFingerprint &&
		s.IPv6RouteFingerprint == other.IPv6RouteFingerprint &&
		s.IPv4RuleFingerprint == other.IPv4RuleFingerprint &&
		s.IPv6RuleFingerprint == other.IPv6RuleFingerprint &&
		slices.Equal(s.Interfaces, other.Interfaces)
}

// ConnectivityChanged reports a newly usable path or a change to an existing
// usable path. Netlink events themselves never establish connectivity.
func (s HostNetworkSnapshot) ConnectivityChanged(previous HostNetworkSnapshot) bool {
	if !s.Ready() {
		return false
	}
	return !previous.Ready() || !s.Equal(previous)
}

type hostNetworkData struct {
	links   []netlink.Link
	routes4 []netlink.Route
	routes6 []netlink.Route
	rules4  []netlink.Rule
	rules6  []netlink.Rule
	addrs4  map[int][]netlink.Addr
	addrs6  map[int][]netlink.Addr
}

type hostNetworkSnapshotFunc func() (HostNetworkSnapshot, error)

type hostNetworkSubscriptions struct {
	link  func(<-chan struct{}) (<-chan netlink.LinkUpdate, error)
	addr  func(<-chan struct{}) (<-chan netlink.AddrUpdate, error)
	route func(<-chan struct{}) (<-chan netlink.RouteUpdate, error)
	rule  func(<-chan struct{}) (<-chan struct{}, error)
}

// HostNetworkMonitor coalesces link/address/route events and rebuilds host
// state from fresh dumps. Callbacks run outside the monitor lock.
type HostNetworkMonitor struct {
	closed context.Context
	close  context.CancelFunc
	done   chan struct{}

	mu        sync.RWMutex
	snapshot  HostNetworkSnapshot
	callbacks []func(HostNetworkSnapshot, HostNetworkSnapshot)

	snapshotFn      hostNetworkSnapshotFunc
	subscriptions   *hostNetworkSubscriptions
	debounce        time.Duration
	resyncInterval  time.Duration
	subscriptionEnd chan struct{}
}

func NewHostNetworkMonitor() *HostNetworkMonitor {
	subscriptionEnd := make(chan struct{})

	subscribeError := func(kind string) func(error) {
		return func(err error) { log.Debugf("%s subscription: %v", kind, err) }
	}
	subscriptions := &hostNetworkSubscriptions{
		link: func(done <-chan struct{}) (<-chan netlink.LinkUpdate, error) {
			ch := make(chan netlink.LinkUpdate, 16)
			// reconcile performs the authoritative dump after subscriptions start.
			// ListExisting would broadcast its dump request to other link subscribers.
			err := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
				ErrorCallback: subscribeError("link"),
			})
			return ch, err
		},
		addr: func(done <-chan struct{}) (<-chan netlink.AddrUpdate, error) {
			ch := make(chan netlink.AddrUpdate, 16)
			err := netlink.AddrSubscribeWithOptions(ch, done, netlink.AddrSubscribeOptions{
				ErrorCallback: subscribeError("address"),
			})
			return ch, err
		},
		route: func(done <-chan struct{}) (<-chan netlink.RouteUpdate, error) {
			ch := make(chan netlink.RouteUpdate, 16)
			err := netlink.RouteSubscribeWithOptions(ch, done, netlink.RouteSubscribeOptions{
				ErrorCallback: subscribeError("route"),
			})
			return ch, err
		},
		rule: func(done <-chan struct{}) (<-chan struct{}, error) {
			return subscribeRuleUpdates(done, subscribeError("rule"))
		},
	}
	return newHostNetworkMonitor(currentHostNetworkSnapshot, nil, nil, nil, nil, subscriptionEnd, subscriptions,
		hostNetworkDebounceInterval, hostNetworkResyncInterval)
}

func subscribeRuleUpdates(done <-chan struct{}, errorCallback func(error)) (<-chan struct{}, error) {
	socket, err := nl.Subscribe(unix.NETLINK_ROUTE, unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE)
	if err != nil {
		return nil, err
	}
	updates := make(chan struct{}, 16)
	if done != nil {
		go func() {
			<-done
			socket.Close()
		}()
	}
	go func() {
		defer close(updates)
		for {
			messages, from, err := socket.Receive()
			if err != nil {
				if errorCallback != nil {
					errorCallback(fmt.Errorf("receive failed: %w", err))
				}
				return
			}
			if from.Pid != nl.PidKernel {
				if errorCallback != nil {
					errorCallback(fmt.Errorf("wrong sender portid %d, expected %d", from.Pid, nl.PidKernel))
				}
				continue
			}
			for _, message := range messages {
				if message.Header.Type == unix.RTM_NEWRULE || message.Header.Type == unix.RTM_DELRULE {
					updates <- struct{}{}
				}
			}
		}
	}()
	return updates, nil
}

func newHostNetworkMonitor(
	snapshotFn hostNetworkSnapshotFunc,
	linkCh <-chan netlink.LinkUpdate,
	addrCh <-chan netlink.AddrUpdate,
	routeCh <-chan netlink.RouteUpdate,
	ruleCh <-chan struct{},
	subscriptionEnd chan struct{},
	subscriptions *hostNetworkSubscriptions,
	debounce time.Duration,
	resyncInterval time.Duration,
) *HostNetworkMonitor {
	closed, cancel := context.WithCancel(context.Background())
	m := &HostNetworkMonitor{
		closed:          closed,
		close:           cancel,
		done:            make(chan struct{}),
		snapshotFn:      snapshotFn,
		subscriptions:   subscriptions,
		debounce:        debounce,
		resyncInterval:  resyncInterval,
		subscriptionEnd: subscriptionEnd,
	}
	go m.run(linkCh, addrCh, routeCh, ruleCh)
	return m
}

// Register adds a snapshot observer. Callbacks must treat both snapshots as immutable.
func (m *HostNetworkMonitor) Register(callback func(HostNetworkSnapshot, HostNetworkSnapshot)) {
	if callback == nil {
		return
	}
	m.mu.Lock()
	m.callbacks = append(m.callbacks, callback)
	m.mu.Unlock()
}

func (m *HostNetworkMonitor) Snapshot() HostNetworkSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := m.snapshot
	snapshot.Interfaces = slices.Clone(snapshot.Interfaces)
	return snapshot
}

func (m *HostNetworkMonitor) reconcile() bool {
	next, err := m.snapshotFn()
	if err != nil {
		log.Debugf("Failed to reconcile host network state: %v", err)
		return false
	}
	next.Interfaces = slices.Clone(next.Interfaces)
	m.mu.Lock()
	previous := m.snapshot
	if previous.revision != 0 && next.Equal(previous) {
		m.mu.Unlock()
		return true
	}
	next.revision = previous.revision + 1
	m.snapshot = next
	callbacks := slices.Clone(m.callbacks)
	m.mu.Unlock()
	for _, callback := range callbacks {
		callback(previous, next)
	}
	return true
}

func (m *HostNetworkMonitor) run(
	linkCh <-chan netlink.LinkUpdate,
	addrCh <-chan netlink.AddrUpdate,
	routeCh <-chan netlink.RouteUpdate,
	ruleCh <-chan struct{},
) {
	defer close(m.done)
	defer func() {
		if m.subscriptionEnd == nil {
			return
		}
		close(m.subscriptionEnd)
		// The netlink package sends updates synchronously. Drain the channels
		// after closing its sockets so blocked subscription goroutines can exit.
		for linkCh != nil || addrCh != nil || routeCh != nil || ruleCh != nil {
			select {
			case _, ok := <-linkCh:
				if !ok {
					linkCh = nil
				}
			case _, ok := <-addrCh:
				if !ok {
					addrCh = nil
				}
			case _, ok := <-routeCh:
				if !ok {
					routeCh = nil
				}
			case _, ok := <-ruleCh:
				if !ok {
					ruleCh = nil
				}
			}
		}
	}()

	periodic := time.NewTicker(m.resyncInterval)
	defer periodic.Stop()
	subscriptionRetry := time.NewTicker(hostNetworkRetryInterval)
	defer subscriptionRetry.Stop()
	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time
	markDirty := func() {
		if debounceCh != nil {
			return
		}
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(m.debounce)
		} else {
			debounceTimer.Reset(m.debounce)
		}
		debounceCh = debounceTimer.C
	}
	restoreSubscriptions := func() {
		if m.subscriptions == nil {
			return
		}
		if linkCh == nil && m.subscriptions.link != nil {
			var err error
			if linkCh, err = m.subscriptions.link(m.subscriptionEnd); err != nil {
				log.Debugf("link subscription: %v", err)
				linkCh = nil
			} else {
				markDirty()
			}
		}
		if addrCh == nil && m.subscriptions.addr != nil {
			var err error
			if addrCh, err = m.subscriptions.addr(m.subscriptionEnd); err != nil {
				log.Debugf("address subscription: %v", err)
				addrCh = nil
			} else {
				markDirty()
			}
		}
		if routeCh == nil && m.subscriptions.route != nil {
			var err error
			if routeCh, err = m.subscriptions.route(m.subscriptionEnd); err != nil {
				log.Debugf("route subscription: %v", err)
				routeCh = nil
			} else {
				markDirty()
			}
		}
		if ruleCh == nil && m.subscriptions.rule != nil {
			var err error
			if ruleCh, err = m.subscriptions.rule(m.subscriptionEnd); err != nil {
				log.Debugf("rule subscription: %v", err)
				ruleCh = nil
			} else {
				markDirty()
			}
		}
	}
	var retryTimer *time.Timer
	var retryCh <-chan time.Time
	scheduleRetry := func() {
		if retryCh != nil {
			return
		}
		if retryTimer == nil {
			retryTimer = time.NewTimer(hostNetworkRetryInterval)
		} else {
			retryTimer.Reset(hostNetworkRetryInterval)
		}
		retryCh = retryTimer.C
	}
	stopRetry := func() {
		if retryCh == nil {
			return
		}
		if !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
		retryCh = nil
	}
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		if retryTimer != nil {
			retryTimer.Stop()
		}
	}()
	restoreSubscriptions()
	if !m.reconcile() {
		scheduleRetry()
	}

	for {
		select {
		case <-m.closed.Done():
			return
		case _, ok := <-linkCh:
			if !ok {
				linkCh = nil
				markDirty()
				continue
			}
			markDirty()
		case _, ok := <-addrCh:
			if !ok {
				addrCh = nil
				markDirty()
				continue
			}
			markDirty()
		case _, ok := <-routeCh:
			if !ok {
				routeCh = nil
				markDirty()
				continue
			}
			markDirty()
		case _, ok := <-ruleCh:
			if !ok {
				ruleCh = nil
				markDirty()
				continue
			}
			markDirty()
		case <-debounceCh:
			debounceCh = nil
			if m.reconcile() {
				stopRetry()
			} else {
				scheduleRetry()
			}
		case <-retryCh:
			retryCh = nil
			if !m.reconcile() {
				scheduleRetry()
			}
		case <-periodic.C:
			if m.reconcile() {
				stopRetry()
			} else {
				scheduleRetry()
			}
		case <-subscriptionRetry.C:
			restoreSubscriptions()
		}
	}
}

func (m *HostNetworkMonitor) Close() error {
	m.close()
	<-m.done
	return nil
}

func currentHostNetworkSnapshot() (HostNetworkSnapshot, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return HostNetworkSnapshot{}, err
	}
	routes4, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return HostNetworkSnapshot{}, err
	}
	routes6, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return HostNetworkSnapshot{}, err
	}
	rules4, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return HostNetworkSnapshot{}, err
	}
	// IPv6 routing can exist without CONFIG_IPV6_MULTIPLE_TABLES. In that
	// case the kernel has no IPv6 RPDB and RTM_GETRULE returns EAFNOSUPPORT;
	// IPv4 discovery must continue independently.
	rules6, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		if !errors.Is(err, unix.EAFNOSUPPORT) {
			return HostNetworkSnapshot{}, err
		}
		rules6 = nil
	}
	data := hostNetworkData{
		links:   links,
		routes4: routes4,
		routes6: routes6,
		rules4:  rules4,
		rules6:  rules6,
		addrs4:  make(map[int][]netlink.Addr, len(links)),
		addrs6:  make(map[int][]netlink.Addr, len(links)),
	}
	for _, link := range links {
		index := link.Attrs().Index
		if data.addrs4[index], err = netlink.AddrList(link, netlink.FAMILY_V4); err != nil {
			return HostNetworkSnapshot{}, err
		}
		if data.addrs6[index], err = netlink.AddrList(link, netlink.FAMILY_V6); err != nil {
			return HostNetworkSnapshot{}, err
		}
	}
	return buildHostNetworkSnapshot(data), nil
}

func buildHostNetworkSnapshot(data hostNetworkData) HostNetworkSnapshot {
	type routeFamilies struct{ ipv4, ipv6 bool }
	families := make(map[int]routeFamilies)
	linkGroups := make(map[int]uint32, len(data.links))
	for _, link := range data.links {
		linkGroups[link.Attrs().Index] = link.Attrs().Group
	}
	collectRoutes := func(routes []netlink.Route, rules []netlink.Rule, ipv4 bool) string {
		rulesByTable := make(map[int][]netlink.Rule, len(rules))
		for _, rule := range rules {
			if rule.Table != unix.RT_TABLE_UNSPEC {
				rulesByTable[rule.Table] = append(rulesByTable[rule.Table], rule)
			}
		}
		fingerprints := make([]string, 0, len(routes))
		for _, route := range routes {
			if !isDefaultUnicastRoute(route) {
				continue
			}
			tableRules := rulesByTable[route.Table]
			if len(tableRules) == 0 {
				continue
			}
			indices := unsuppressedDefaultRouteLinkIndices(routeLinkIndices(route), tableRules, linkGroups)
			if len(indices) == 0 {
				continue
			}
			for _, index := range indices {
				family := families[index]
				if ipv4 {
					family.ipv4 = true
				} else {
					family.ipv6 = true
				}
				families[index] = family
			}
			fingerprints = append(fingerprints, routeFingerprint(route))
		}
		sort.Strings(fingerprints)
		return strings.Join(fingerprints, "|")
	}

	snapshot := HostNetworkSnapshot{
		IPv4RouteFingerprint: collectRoutes(data.routes4, data.rules4, true),
		IPv6RouteFingerprint: collectRoutes(data.routes6, data.rules6, false),
		IPv4RuleFingerprint:  rulesFingerprint(data.rules4),
		IPv6RuleFingerprint:  rulesFingerprint(data.rules6),
	}
	for _, link := range data.links {
		attrs := link.Attrs()
		family, ok := families[attrs.Index]
		if !ok {
			continue
		}
		intf := DefaultRouteInterface{
			Index:       attrs.Index,
			Name:        attrs.Name,
			IPv4Default: family.ipv4,
			IPv6Default: family.ipv6,
		}
		if linkOperational(attrs) {
			if family.ipv4 {
				intf.IPv4Source = usableAddress(data.addrs4[attrs.Index], true)
			}
			if family.ipv6 {
				intf.IPv6Source = usableAddress(data.addrs6[attrs.Index], false)
			}
		}
		snapshot.Interfaces = append(snapshot.Interfaces, intf)
	}
	sort.Slice(snapshot.Interfaces, func(i, j int) bool {
		return snapshot.Interfaces[i].Index < snapshot.Interfaces[j].Index
	})
	return snapshot
}

func unsuppressedDefaultRouteLinkIndices(indices []int, rules []netlink.Rule, linkGroups map[int]uint32) []int {
	reachable := make([]int, 0, len(indices))
	for _, rule := range rules {
		// A default route has prefix length zero, so every configured prefix
		// suppression threshold rejects it and continues with the next rule.
		if rule.SuppressPrefixlen >= 0 {
			continue
		}
		for _, index := range indices {
			if group, exists := linkGroups[index]; exists &&
				rule.SuppressIfgroup >= 0 && group == uint32(rule.SuppressIfgroup) {
				continue
			}
			if !slices.Contains(reachable, index) {
				reachable = append(reachable, index)
			}
		}
	}
	sort.Ints(reachable)
	return reachable
}

func rulesFingerprint(rules []netlink.Rule) string {
	fingerprints := make([]string, 0, len(rules))
	for _, rule := range rules {
		mask := ""
		if rule.Mask != nil {
			mask = fmt.Sprint(*rule.Mask)
		}
		portRange := func(r *netlink.RulePortRange) string {
			if r == nil {
				return ""
			}
			return fmt.Sprintf("%d-%d", r.Start, r.End)
		}
		uidRange := ""
		if rule.UIDRange != nil {
			uidRange = fmt.Sprintf("%d-%d", rule.UIDRange.Start, rule.UIDRange.End)
		}
		fingerprints = append(fingerprints, fmt.Sprintf(
			"priority=%d,family=%d,table=%d,mark=%d,mask=%s,tos=%d,tun=%d,goto=%d,src=%s,dst=%s,flow=%d,iif=%q,oif=%q,suppress-ifgroup=%d,suppress-prefixlen=%d,invert=%t,dport=%s,sport=%s,ipproto=%d,uid=%s,protocol=%d,type=%d",
			rule.Priority, rule.Family, rule.Table, rule.Mark, mask, rule.Tos, rule.TunID, rule.Goto,
			rule.Src, rule.Dst, rule.Flow, rule.IifName, rule.OifName, rule.SuppressIfgroup,
			rule.SuppressPrefixlen, rule.Invert, portRange(rule.Dport), portRange(rule.Sport),
			rule.IPProto, uidRange, rule.Protocol, rule.Type))
	}
	sort.Strings(fingerprints)
	return strings.Join(fingerprints, "|")
}

func isDefaultUnicastRoute(route netlink.Route) bool {
	if route.Type != unix.RTN_UNICAST {
		return false
	}
	if route.Dst == nil {
		return true
	}
	ones, _ := route.Dst.Mask.Size()
	return ones == 0
}

func routeLinkIndices(route netlink.Route) []int {
	if len(route.MultiPath) == 0 {
		if route.LinkIndex == 0 {
			return nil
		}
		return []int{route.LinkIndex}
	}
	indices := make([]int, 0, len(route.MultiPath))
	for _, nextHop := range route.MultiPath {
		if nextHop.Flags&(unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) == 0 && nextHop.LinkIndex != 0 && !slices.Contains(indices, nextHop.LinkIndex) {
			indices = append(indices, nextHop.LinkIndex)
		}
	}
	sort.Ints(indices)
	return indices
}

func routeFingerprint(route netlink.Route) string {
	parts := []string{fmt.Sprintf("table=%d,type=%d,priority=%d,link=%d,gw=%s,src=%s",
		route.Table, route.Type, route.Priority, route.LinkIndex, route.Gw, route.Src)}
	for _, nextHop := range route.MultiPath {
		parts = append(parts, "nexthop="+nextHop.String())
	}
	sort.Strings(parts[1:])
	return strings.Join(parts, ";")
}

func linkOperational(attrs *netlink.LinkAttrs) bool {
	if attrs.Flags&net.FlagUp == 0 {
		return false
	}
	switch attrs.OperState {
	case netlink.OperDown, netlink.OperLowerLayerDown, netlink.OperTesting, netlink.OperDormant, netlink.OperNotPresent:
		return false
	case netlink.OperUp:
		return true
	default:
		return attrs.RawFlags&unix.IFF_LOWER_UP != 0 || attrs.OperState == netlink.OperUnknown
	}
}

func usableAddress(addrs []netlink.Addr, ipv4 bool) string {
	usable := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil || !addr.IP.IsGlobalUnicast() {
			continue
		}
		is4 := addr.IP.To4() != nil
		if is4 != ipv4 {
			continue
		}
		if addr.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED|unix.IFA_F_DEPRECATED) != 0 {
			continue
		}
		usable = append(usable, addr.IP.String())
	}
	sort.Strings(usable)
	if len(usable) == 0 {
		return ""
	}
	return usable[0]
}
