/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

var testNetworkType = &common.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
}

type fakeDialer struct{}

func (fakeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (fakeDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

var selectorDialerSequence atomic.Uint64

func newUncheckedDialer(t *testing.T, name string) *dialer.Dialer {
	t.Helper()
	id := selectorDialerSequence.Add(1)
	return dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: fakeDialer{}}), &dialer.GlobalOption{}, &dialer.Property{
		Name: name,
		Link: fmt.Sprintf("test://%s/%d", name, id),
	}, false, "")
}

func newCheckedDialer(t *testing.T, name string) *dialer.Dialer {
	t.Helper()
	id := selectorDialerSequence.Add(1)
	return dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: fakeDialer{}}), &dialer.GlobalOption{}, &dialer.Property{
		Name: name,
		Link: fmt.Sprintf("test://%s/%d", name, id),
	}, true, "")
}

func newSelectorTestGroup(t *testing.T, dialers []*dialer.Dialer, annotations []*dialer.Annotation, policy dialer.DialerSelectionPolicy, callback func(bool, *common.NetworkType) error) *DialerGroup {
	t.Helper()
	g := &DialerGroup{
		Name:               t.Name(),
		Kind:               GroupKindSelector,
		Dialers:            dialers,
		selectionPolicy:    policy,
		dialerToAnnotation: make(map[*dialer.Dialer]*dialer.Annotation, len(dialers)),
		publishNetwork:     callback,
	}
	g.selectionIndex.Store(int64(policy.FixedIndex))
	for i, d := range dialers {
		g.dialerToAnnotation[d] = annotations[i]
	}
	switch policy.Policy {
	case consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		consts.DialerSelectionPolicy_MinLastLatency:
		g.selector = &latencyBasedSelector{dialerGroup: g}
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func emptyAnnotations(n int) []*dialer.Annotation {
	annotations := make([]*dialer.Annotation, n)
	for i := range annotations {
		annotations[i] = new(dialer.Annotation)
	}
	return annotations
}

func TestSaturatingDurationAdd(t *testing.T) {
	maxDuration := time.Duration(1<<63 - 1)
	minDuration := time.Duration(-1 << 63)
	if got := saturatingDurationAdd(maxDuration, time.Nanosecond); got != maxDuration {
		t.Fatalf("positive overflow = %v, want %v", got, maxDuration)
	}
	if got := saturatingDurationAdd(minDuration, -time.Nanosecond); got != minDuration {
		t.Fatalf("negative overflow = %v, want %v", got, minDuration)
	}
}

func TestFixedSelectorUsesConfiguredDialer(t *testing.T) {
	dialers := []*dialer.Dialer{
		newUncheckedDialer(t, "first"),
		newUncheckedDialer(t, "second"),
	}
	g := newSelectorTestGroup(t, dialers, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 1,
	}, nil)
	selected, err := g.Select(testNetworkType)
	if err != nil || selected != dialers[1] {
		t.Fatalf("Select = %v, %v; want second", selected, err)
	}
	if got := g.SelectedDialer(testNetworkType); got != dialers[1] {
		t.Fatalf("SelectedDialer = %v, want second", got)
	}
}

func TestDefaultPolicyMeansFixedZero(t *testing.T) {
	dialers := []*dialer.Dialer{
		newUncheckedDialer(t, "first"),
		newUncheckedDialer(t, "backup"),
	}
	g := newSelectorTestGroup(t, dialers, emptyAnnotations(2), dialer.DialerSelectionPolicy{}, nil)
	selected, err := g.Select(testNetworkType)
	if err != nil || selected != dialers[0] {
		t.Fatalf("default Select = %v, %v; want first", selected, err)
	}
	_ = dialers[0].Close()
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("default fixed selector used backup: %v", err)
	}
}

func TestRandomSelectorUsesHighestPriorityTier(t *testing.T) {
	dialers := []*dialer.Dialer{
		newUncheckedDialer(t, "low"),
		newUncheckedDialer(t, "high-a"),
		newUncheckedDialer(t, "high-b"),
	}
	annotations := emptyAnnotations(3)
	annotations[1].Priority = 10
	annotations[2].Priority = 10
	g := newSelectorTestGroup(t, dialers, annotations, dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random}, nil)
	seen := map[*dialer.Dialer]bool{}
	for i := 0; i < 100; i++ {
		selected, err := g.Select(testNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		if selected == dialers[0] {
			t.Fatal("random selector returned lower-priority dialer")
		}
		seen[selected] = true
	}
	if !seen[dialers[1]] || !seen[dialers[2]] {
		t.Fatalf("highest-priority tier was not sampled: %v", seen)
	}
	if selected := g.SelectedDialer(testNetworkType); selected != nil {
		t.Fatalf("random selector reported stable selection %v", selected)
	}
}

func TestLatencySelectorFallsBackWhenSelectedDialerCloses(t *testing.T) {
	dialers := []*dialer.Dialer{
		newUncheckedDialer(t, "slower"),
		newUncheckedDialer(t, "preferred"),
	}
	annotations := emptyAnnotations(2)
	annotations[0].AddLatency = time.Second
	g := newSelectorTestGroup(t, dialers, annotations, dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, nil)
	selected, err := g.Select(testNetworkType)
	if err != nil || selected != dialers[1] {
		t.Fatalf("initial Select = %v, %v; want preferred", selected, err)
	}
	_ = dialers[1].Close()
	selected, err = g.Select(testNetworkType)
	if err != nil || selected != dialers[0] {
		t.Fatalf("fallback Select = %v, %v; want slower", selected, err)
	}
}

func TestLatencySelectorIgnoresToleranceUntilEnabled(t *testing.T) {
	dialers := []*dialer.Dialer{
		newUncheckedDialer(t, "first"),
		newUncheckedDialer(t, "second"),
	}
	annotations := emptyAnnotations(2)
	annotations[0].AddLatency = 100 * time.Millisecond
	annotations[1].AddLatency = 200 * time.Millisecond
	g := newSelectorTestGroup(t, dialers, annotations, dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinLastLatency,
	}, nil)
	selector := g.selector
	selector.tolerance = 20 * time.Millisecond

	if selected, err := g.Select(testNetworkType); err != nil || selected != dialers[0] {
		t.Fatalf("initial Select = %v, %v; want first", selected, err)
	}
	annotations[1].AddLatency = 90 * time.Millisecond
	selector.Refresh(dialers[1], dialer.SelectionForceNone)
	if selected := g.SelectedDialer(testNetworkType); selected != dialers[1] {
		t.Fatalf("startup selection = %v, want second", selected)
	}
	if selected := g.SelectedDialer(common.NetworkTCP6.NetworkType()); selected != dialers[1] {
		t.Fatalf("startup tcp6 selection = %v, want second", selected)
	}

	g.EnableSelectionTolerance()
	annotations[0].AddLatency = 80 * time.Millisecond
	selector.Refresh(dialers[0], dialer.SelectionForceNone)
	if selected := g.SelectedDialer(testNetworkType); selected != dialers[1] {
		t.Fatalf("steady-state selection = %v, want second", selected)
	}
	selector.Refresh(dialers[0], dialer.SelectionForceFor(testNetworkType.Index()))
	if selected := g.SelectedDialer(testNetworkType); selected != dialers[0] {
		t.Fatalf("forced selection = %v, want first", selected)
	}
	if selected := g.SelectedDialer(common.NetworkTCP6.NetworkType()); selected != dialers[1] {
		t.Fatalf("unforced tcp6 selection = %v, want second", selected)
	}
}

func TestLatencySelectorToleranceDoesNotOverflow(t *testing.T) {
	dialers := []*dialer.Dialer{
		newUncheckedDialer(t, "first"),
		newUncheckedDialer(t, "second"),
	}
	minimum := time.Duration(-1 << 63)
	annotations := emptyAnnotations(2)
	annotations[0].AddLatency = minimum + 10
	annotations[1].AddLatency = minimum + 20
	g := newSelectorTestGroup(t, dialers, annotations, dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinLastLatency,
	}, nil)
	selector := g.selector
	selector.tolerance = 20

	if selected, err := g.Select(testNetworkType); err != nil || selected != dialers[0] {
		t.Fatalf("initial Select = %v, %v; want first", selected, err)
	}
	g.EnableSelectionTolerance()
	annotations[1].AddLatency = minimum
	selector.Refresh(dialers[1], dialer.SelectionForceNone)
	if selected := g.SelectedDialer(testNetworkType); selected != dialers[0] {
		t.Fatalf("overflowing tolerance switched to %v", selected)
	}
}

func TestGroupAvailabilityReadsCurrentDialerState(t *testing.T) {
	d := newUncheckedDialer(t, "node")
	var changes [common.NetworkTypeCount]bool
	g := newSelectorTestGroup(t, []*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{},
		func(available bool, networkType *common.NetworkType) error {
			changes[networkType.Index()] = available
			return nil
		})
	g.DialerChanged(d, dialer.SelectionForceNone)
	for i, available := range changes {
		if !available {
			t.Fatalf("network %d was not published available", i)
		}
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateAvailable {
		t.Fatalf("group state = %q, want available", state)
	}
	_ = d.Close()
	g.DialerChanged(d, dialer.SelectionForceNone)
	for i, available := range changes {
		if available {
			t.Fatalf("network %d remained available", i)
		}
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateUnavailable {
		t.Fatalf("group state = %q, want unavailable", state)
	}
}

func TestDialerGroupStartsChecking(t *testing.T) {
	stats.DefaultStore.Reconcile(nil, map[string]struct{}{t.Name(): {}})
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	d := newCheckedDialer(t, t.Name())
	g := NewDialerGroup(&dialer.GlobalOption{}, t.Name(), GroupKindSelector,
		[]*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = g.Close() })
	ready, err := g.StartConnectivityChecks(make(chan struct{}))
	if err != nil {
		t.Fatal(err)
	}
	if ready != g.startupReady {
		t.Fatal("connectivity startup returned a different barrier")
	}
	state, history := g.Connectivity()
	if state != stats.GroupStateChecking {
		t.Fatalf("initial group state = %q, want checking", state)
	}
	for i, state := range history.Recent.States {
		if state != stats.GroupHistoryUnknown {
			t.Fatalf("initial history bucket %d = %q, want unknown", i, state)
		}
	}
	if availability := stats.DefaultStore.GetGroup(g.Name); availability.Seen {
		t.Fatalf("initial checking was recorded as an availability observation: %+v", availability)
	}
	select {
	case <-ready:
		t.Fatal("checking group reported initial connectivity ready")
	default:
	}
}

func TestDialerGroupStartupReadyWaitsForNetworkPublication(t *testing.T) {
	pending := newCheckedDialer(t, "pending")
	available := newUncheckedDialer(t, "available")
	publicationBlocked := make(chan struct{})
	releasePublication := make(chan struct{})
	g := newSelectorTestGroup(t, []*dialer.Dialer{pending, available}, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinLastLatency,
	}, func(available bool, networkType *common.NetworkType) error {
		if available && networkType.Index() == common.NetworkTCP6 {
			close(publicationBlocked)
			<-releasePublication
		}
		return nil
	})

	if err := g.initializeConnectivity(); err != nil {
		t.Fatal(err)
	}

	notified := make(chan struct{})
	go func() {
		g.DialerChanged(available, dialer.SelectionForceNone)
		close(notified)
	}()
	<-publicationBlocked
	select {
	case <-g.startupReady:
		close(releasePublication)
		t.Fatal("startup barrier opened before all network states were published")
	default:
	}
	close(releasePublication)
	<-notified
	select {
	case <-g.startupReady:
	default:
		t.Fatal("startup barrier remained closed after network publication")
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateAvailable {
		t.Fatalf("group state = %q, want available", state)
	}
}

func TestDialerGroupCloseDrainsNotifications(t *testing.T) {
	d := newUncheckedDialer(t, "available")
	publicationBlocked := make(chan struct{})
	releasePublication := make(chan struct{})
	g := newSelectorTestGroup(t, []*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{},
		func(available bool, _ *common.NetworkType) error {
			if available {
				select {
				case <-publicationBlocked:
				default:
					close(publicationBlocked)
					<-releasePublication
				}
			}
			return nil
		})

	notified := make(chan struct{})
	go func() {
		g.DialerChanged(d, dialer.SelectionForceNone)
		close(notified)
	}()
	<-publicationBlocked
	closed := make(chan struct{})
	go func() {
		_ = g.Close()
		close(closed)
	}()
	select {
	case <-closed:
		close(releasePublication)
		t.Fatal("group closed before its in-flight notification completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(releasePublication)
	<-notified
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("group did not close after its notification completed")
	}
}

func TestDialerGroupInitialReadyWhenBlockingChecksCompleteUnavailable(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1"}},
		CheckInterval:     time.Hour,
		CheckIntervalMax:  time.Hour,
	}
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: fakeDialer{}}), option, &dialer.Property{
		Name: t.Name(),
		Link: fmt.Sprintf("test://%s/%d", t.Name(), selectorDialerSequence.Add(1)),
	}, true, "")
	g := NewDialerGroup(option, t.Name(), GroupKindSelector,
		[]*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = g.Close() })
	start := make(chan struct{})
	ready, err := g.StartConnectivityChecks(start)
	if err != nil {
		t.Fatal(err)
	}
	close(start)
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("completed unavailable check did not release the startup barrier")
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateUnavailable {
		t.Fatalf("group state = %q, want unavailable", state)
	}
}

func waitForInitialCheck(t *testing.T, d *dialer.Dialer) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !d.ConnectivitySnapshot().InitialCheckDone {
		if time.Now().After(deadline) {
			t.Fatalf("dialer %q did not complete its initial check", d.Name)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDialerGroupWaitsForAllUnavailableCandidates(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1"}},
		CheckInterval:     time.Hour,
		CheckIntervalMax:  time.Hour,
	}
	newDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: fakeDialer{}}), option, &dialer.Property{
			Name: name,
			Link: fmt.Sprintf("test://%s/%d", name, selectorDialerSequence.Add(1)),
		}, true, "")
	}
	first, second := newDialer("first"), newDialer("second")
	g := NewDialerGroup(option, t.Name(), GroupKindSelector,
		[]*dialer.Dialer{first, second}, emptyAnnotations(2),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, nil)
	t.Cleanup(func() { _ = g.Close() })
	if err := g.initializeConnectivity(); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	close(start)
	first.ActivateCheck(start)
	waitForInitialCheck(t, first)
	g.DialerChanged(first, dialer.SelectionForceNone)
	select {
	case <-g.startupReady:
		t.Fatal("one unavailable candidate released startup while another check was pending")
	default:
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateChecking {
		t.Fatalf("partially checked group state = %q, want checking", state)
	}
	second.ActivateCheck(start)
	select {
	case <-g.startupReady:
	case <-time.After(time.Second):
		t.Fatal("completed unavailable checks did not release startup")
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateUnavailable {
		t.Fatalf("group state = %q, want unavailable", state)
	}
}

func TestDialerGroupInitialReadyWaitsWhileCandidatesArePending(t *testing.T) {
	dialers := []*dialer.Dialer{
		newCheckedDialer(t, "first"),
		newCheckedDialer(t, "second"),
	}
	g := newSelectorTestGroup(t, dialers, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinLastLatency,
	}, nil)
	// Retained availability from a previous control plane must not count as a
	// result from either dialer in the current startup round.
	identities := make(map[string]stats.NodeIdentity, len(dialers))
	for _, d := range dialers {
		identities[d.StatsKey()] = stats.NodeIdentity{Subtag: d.SubscriptionTag, Name: d.Name}
	}
	stats.DefaultStore.Reconcile(identities, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	for _, d := range dialers {
		stats.DefaultStore.RecordNodeCheck(d.StatsKey(), false, time.Now())
	}
	if err := g.initializeConnectivity(); err != nil {
		t.Fatal(err)
	}

	g.DialerChanged(dialers[0], dialer.SelectionForceNone)
	select {
	case <-g.startupReady:
		t.Fatal("group became ready while another candidate was still pending")
	default:
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateChecking {
		t.Fatalf("partially checked group state = %q, want checking", state)
	}

	g.DialerChanged(dialers[1], dialer.SelectionForceNone)
	select {
	case <-g.startupReady:
		t.Fatal("pending candidates released the group startup barrier")
	default:
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateChecking {
		t.Fatalf("group state = %q, want checking", state)
	}
}

func TestDialerGroupCheckAsyncAppliesToAllCandidates(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1"}},
		CheckInterval:     time.Hour,
		CheckIntervalMax:  time.Hour,
	}
	dialers := []*dialer.Dialer{newCheckedDialer(t, "first"), newCheckedDialer(t, "second")}
	for _, d := range dialers {
		d.GlobalOption = option
	}
	g := NewDialerGroup(option, t.Name(), GroupKindSelector, dialers, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 1,
	}, nil)
	t.Cleanup(func() { _ = g.Close() })
	// Routing usage is resolved after construction, before checks start.
	g.CheckAsync = true
	start := make(chan struct{})
	ready, err := g.StartConnectivityChecks(start)
	if err != nil {
		t.Fatal(err)
	}
	if ready != nil {
		t.Fatal("asynchronous group participated in the startup barrier")
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateChecking {
		t.Fatalf("async group state before checks = %q, want checking", state)
	}
	close(start)
	for _, d := range dialers {
		waitForInitialCheck(t, d)
	}
	g.DialerChanged(dialers[1], dialer.SelectionForceNone)
	if state, _ := g.Connectivity(); state != stats.GroupStateUnavailable {
		t.Fatalf("async group state after failed checks = %q, want unavailable", state)
	}
}

func TestDialerGroupFixedWaitsOnlyForSelectedCandidate(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1"}},
		CheckInterval:     time.Hour,
		CheckIntervalMax:  time.Hour,
	}
	dialers := []*dialer.Dialer{newCheckedDialer(t, "non-fixed"), newCheckedDialer(t, "fixed")}
	for _, d := range dialers {
		d.GlobalOption = option
	}
	g := NewDialerGroup(option, t.Name(), GroupKindSelector, dialers, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 1,
	}, nil)
	t.Cleanup(func() { _ = g.Close() })
	if err := g.initializeConnectivity(); err != nil {
		t.Fatal(err)
	}
	if g.startupReady == nil {
		t.Fatal("synchronous fixed group skipped the startup barrier")
	}
	start := make(chan struct{})
	close(start)
	dialers[1].ActivateCheck(start)
	select {
	case <-g.startupReady:
	case <-time.After(time.Second):
		t.Fatal("completed fixed candidate did not release startup")
	}
	if dialers[0].ConnectivitySnapshot().InitialCheckDone {
		t.Fatal("non-selected candidate unexpectedly completed its initial check")
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateUnavailable {
		t.Fatalf("group state = %q, want unavailable", state)
	}
}

func TestDialerGroupReloadStaysCheckingUntilCurrentCheckCompletes(t *testing.T) {
	name := fmt.Sprintf("%s/%d", t.Name(), selectorDialerSequence.Add(1))
	stats.DefaultStore.Reconcile(nil, map[string]struct{}{name: {}})
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	stats.DefaultStore.RecordGroup(name, true)
	dialers := []*dialer.Dialer{
		newCheckedDialer(t, "non-fixed"),
		newCheckedDialer(t, "fixed"),
	}
	g := NewDialerGroup(&dialer.GlobalOption{}, name, GroupKindSelector,
		dialers, emptyAnnotations(2), dialer.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 1,
		}, nil)
	t.Cleanup(func() { _ = g.Close() })
	if err := g.initializeConnectivity(); err != nil {
		t.Fatal(err)
	}
	availability := stats.DefaultStore.GetGroup(name)
	if !availability.Alive || !availability.LastFailureStartedAt.IsZero() {
		t.Fatalf("reload initialization changed retained availability: %+v", availability)
	}

	g.DialerChanged(dialers[0], dialer.SelectionForceNone)
	availability = stats.DefaultStore.GetGroup(name)
	if !availability.Alive || !availability.LastFailureStartedAt.IsZero() {
		t.Fatalf("non-fixed result changed retained availability: %+v", availability)
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateChecking {
		t.Fatalf("group state after non-fixed result = %q, want checking", state)
	}

	g.DialerChanged(dialers[1], dialer.SelectionForceNone)
	availability = stats.DefaultStore.GetGroup(name)
	if !availability.Alive || !availability.LastFailureStartedAt.IsZero() {
		t.Fatalf("pending fixed result changed retained availability: %+v", availability)
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateChecking {
		t.Fatalf("group state after pending fixed result = %q, want checking", state)
	}
}

func TestEmptyDialerGroupStartsUnavailable(t *testing.T) {
	g := &DialerGroup{Name: t.Name(), Kind: GroupKindSelector}
	stats.DefaultStore.Reconcile(nil, map[string]struct{}{g.Name: {}})
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	if err := g.initializeConnectivity(); err != nil {
		t.Fatal(err)
	}
	if state, _ := g.Connectivity(); state != stats.GroupStateUnavailable {
		t.Fatalf("empty group state = %q, want unavailable", state)
	}
	if availability := stats.DefaultStore.GetGroup(g.Name); !availability.Seen || availability.Alive {
		t.Fatalf("empty group availability = %+v, want observed unavailable", availability)
	}
	if g.startupReady != nil {
		t.Fatal("empty group participated in the startup barrier")
	}
}

func TestCandidateGroupStatsWaitForPublication(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "new group"
		if retained {
			name = "retained group"
		}
		t.Run(name, func(t *testing.T) {
			g := &DialerGroup{Name: t.Name(), Kind: GroupKindSelector}
			groups := map[string]struct{}{g.Name: {}}
			stats.DefaultStore.Reconcile(nil, nil)
			t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
			if retained {
				stats.DefaultStore.Reconcile(nil, groups)
				stats.DefaultStore.RecordGroup(g.Name, true)
			}
			g.DeferStats()
			if _, err := g.StartConnectivityChecks(nil); err != nil {
				t.Fatal(err)
			}
			before := stats.DefaultStore.GetGroup(g.Name)
			if before.Seen != retained || before.Alive != retained {
				t.Fatalf("candidate changed committed group statistics: %+v", before)
			}
			stats.DefaultStore.Reconcile(nil, groups)
			g.PublishStats()
			g.PublishStats()
			if got := stats.DefaultStore.GetGroup(g.Name); !got.Seen || got.Alive {
				t.Fatalf("candidate's completed unavailable state was lost: %+v", got)
			}
		})
	}
}

func TestSingleAlwaysAliveGroupStartsAvailable(t *testing.T) {
	d := newUncheckedDialer(t, t.Name())
	g := NewDialerGroup(&dialer.GlobalOption{}, t.Name(), GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = g.Close() })
	if selected, err := g.Select(testNetworkType); err != nil || selected != d {
		t.Fatalf("Select = %v, %v", selected, err)
	}
}

func TestDialerGroupInitialUnavailableIsSilent(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput := logger.Out
	var output bytes.Buffer
	logger.SetOutput(&output)
	t.Cleanup(func() { logger.SetOutput(previousOutput) })

	g := &DialerGroup{Name: t.Name(), startupReady: make(chan struct{})}
	g.recordAvailability(false, false)
	if strings.Contains(output.String(), "Group is unavailable") {
		t.Fatalf("initial unavailable state was logged:\n%s", output.String())
	}
	g.recordAvailability(false, true)
	if !strings.Contains(output.String(), "Group is available") {
		t.Fatalf("availability transition was not logged:\n%s", output.String())
	}
}

func TestDialerGroupCloseRejectsSelection(t *testing.T) {
	d := newUncheckedDialer(t, t.Name())
	g := newSelectorTestGroup(t, []*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{}, nil)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Select(testNetworkType); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Select after Close = %v, want net.ErrClosed", err)
	}
}
