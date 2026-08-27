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
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
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
	return dialer.NewDialer(netproxy.NewRuntime(fakeDialer{}), &dialer.GlobalOption{}, &dialer.Property{Property: D.Property{
		Name: name,
		Link: fmt.Sprintf("test://%s/%d", name, id),
	}}, dialer.InitialCheckDisabled)
}

func newSelectorTestGroup(t *testing.T, dialers []*dialer.Dialer, annotations []*dialer.Annotation, policy dialer.DialerSelectionPolicy, callback func(bool, *common.NetworkType) error) *DialerGroup {
	t.Helper()
	g := &DialerGroup{
		Name:               t.Name(),
		Kind:               GroupKindSelector,
		Dialers:            dialers,
		selectionPolicy:    policy,
		dialerToAnnotation: make(map[*dialer.Dialer]*dialer.Annotation, len(dialers)),
		availableCallback:  callback,
	}
	for i, d := range dialers {
		g.dialerToAnnotation[d] = annotations[i]
	}
	switch policy.Policy {
	case "", consts.DialerSelectionPolicy_Fixed:
		g.selector = NewFixedSelector(g)
	case consts.DialerSelectionPolicy_Random:
		g.selector = NewRandomSelector(g)
	default:
		g.selector = NewLatencyBasedSelector(g, 0)
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

func TestGroupAvailabilityReadsCurrentDialerState(t *testing.T) {
	d := newUncheckedDialer(t, "node")
	var changes [4]bool
	g := newSelectorTestGroup(t, []*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{},
		func(available bool, networkType *common.NetworkType) error {
			changes[common.NetworkTypeToIndex(networkType)] = available
			return nil
		})
	g.DialerChanged(d)
	for i, available := range changes {
		if !available {
			t.Fatalf("network %d was not published available", i)
		}
	}
	if !g.Available() {
		t.Fatal("group was not available")
	}
	_ = d.Close()
	g.DialerChanged(d)
	for i, available := range changes {
		if available {
			t.Fatalf("network %d remained available", i)
		}
	}
	if g.Available() {
		t.Fatal("group remained available")
	}
}

func TestSingleAlwaysAliveGroupStartsAvailable(t *testing.T) {
	d := newUncheckedDialer(t, t.Name())
	g := NewDialerGroup(&dialer.GlobalOption{}, t.Name(), GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{d}, emptyAnnotations(1), dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = g.Close() })
	if !g.Available() {
		t.Fatal("always-alive singleton started unavailable")
	}
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

	g := &DialerGroup{Name: t.Name()}
	g.publishAvailable(false)
	if strings.Contains(output.String(), "Group is unavailable") {
		t.Fatalf("initial unavailable state was logged:\n%s", output.String())
	}
	g.publishAvailable(true)
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
