/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestManualSelectorPublishesConnectivityAndRetainsUnavailableChoice(t *testing.T) {
	paths := []*dialer.Dialer{newUncheckedDialer(t, "available"), newCheckedDialer(t, "pending")}
	var published [common.NetworkTypeCount]bool
	g := newSelectorTestGroup(t, paths, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Selector, FixedIndexSet: true,
	}, func(available bool, network *common.NetworkType) error {
		published[network.Index()] = available
		return nil
	})
	g.DialerChanged(paths[0], dialer.SelectionForceNone)
	if g.DefaultSelection() != paths[0].StatsID() || g.Selection() != paths[0].StatsID() {
		t.Fatal("selector did not start with the default path")
	}
	if err := g.SetSelection(paths[1].StatsID()); err != nil {
		t.Fatal(err)
	}
	if published != [common.NetworkTypeCount]bool{} {
		t.Fatalf("unavailable selection left networks available: %v", published)
	}
	if g.Selection() != paths[1].StatsID() || g.SelectedDialer(testNetworkType) != nil {
		t.Fatal("requested selection must remain visible while the path is unavailable")
	}
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("unavailable selector used another path: %v", err)
	}
	if err := g.SetSelection(""); err != nil {
		t.Fatal(err)
	}
	selected, err := g.Select(testNetworkType)
	if err != nil || selected != paths[0] {
		t.Fatalf("reset = %v, %v", selected, err)
	}
	for _, available := range published {
		if !available {
			t.Fatal("reset did not restore all network availability")
		}
	}
}

func TestManualSelectorRollsBackFailedPublication(t *testing.T) {
	paths := []*dialer.Dialer{newUncheckedDialer(t, "available"), newCheckedDialer(t, "pending")}
	var published [common.NetworkTypeCount]bool
	failed := false
	g := newSelectorTestGroup(t, paths, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Selector,
	}, func(available bool, network *common.NetworkType) error {
		if !available && !failed {
			failed = true
			return errors.New("kernel update failed")
		}
		published[network.Index()] = available
		return nil
	})
	g.DialerChanged(paths[0], dialer.SelectionForceNone)
	if err := g.SetSelection(paths[1].StatsID()); err == nil {
		t.Fatal("failed kernel update reported success")
	}
	if g.Selection() != paths[0].StatsID() {
		t.Fatal("failed switch changed the current selection")
	}
	for i, available := range published {
		if !available || !g.networkAvailable[i] {
			t.Fatalf("network %d was not rolled back: kernel=%v group=%v", i, published, g.networkAvailable)
		}
	}
}

func TestManualSelectorValidation(t *testing.T) {
	for _, policy := range []dialer.DialerSelectionPolicy{
		{Policy: consts.DialerSelectionPolicy_Fixed},
		{Policy: consts.DialerSelectionPolicy_Selector, FixedIndex: 1},
	} {
		g := newSelectorTestGroup(t, []*dialer.Dialer{newUncheckedDialer(t, "node")}, emptyAnnotations(1), policy, nil)
		if err := g.SetSelection(""); err == nil {
			t.Fatalf("invalid selector %+v accepted a selection", policy)
		}
	}
	g := newSelectorTestGroup(t, []*dialer.Dialer{newUncheckedDialer(t, "node")}, emptyAnnotations(1), dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Selector,
	}, nil)
	if err := g.SetSelection("unknown"); err == nil || g.Selection() != g.Dialers[0].StatsID() || g.DefaultSelection() != "" {
		t.Fatal("unknown ID was accepted or changed selection")
	}
}

func TestManualSelectorStartupUsesRestoredSelection(t *testing.T) {
	for _, trackAll := range []bool{false, true} {
		for _, async := range []bool{false, true} {
			for _, selected := range []int{0, 1} {
				option := &dialer.GlobalOption{
					CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1"}},
					CheckInterval:     time.Hour, CheckIntervalMax: time.Hour,
				}
				paths := []*dialer.Dialer{newCheckedDialer(t, "first"), newCheckedDialer(t, "second")}
				for _, d := range paths {
					d.GlobalOption = option
				}
				g := NewDialerGroup(option, t.Name(), GroupKindSelector, paths, emptyAnnotations(2), dialer.DialerSelectionPolicy{
					Policy: consts.DialerSelectionPolicy_Selector, FixedIndex: 1 - selected, FixedIndexSet: true, TrackAll: trackAll,
				}, nil)
				g.CheckAsync = async
				t.Cleanup(func() { _ = g.Close() })
				if err := g.SetSelection(paths[selected].StatsID()); err != nil {
					t.Fatal(err)
				}
				if err := g.initializeConnectivity(); err != nil {
					t.Fatal(err)
				}
				ready := g.startupReady
				if (ready == nil) != async {
					t.Fatalf("async=%t restored path %d: startup barrier = %v", async, selected, ready)
				}
				select {
				case <-ready:
					t.Fatal("pending selected path released startup")
				default:
				}
				start := make(chan struct{})
				close(start)
				paths[selected].ActivateCheck(start)
				waitForInitialCheck(t, paths[selected])
				if !async {
					select {
					case <-ready:
					case <-time.After(time.Second):
						t.Fatal("completed restored path did not release startup")
					}
				}
				if paths[1-selected].ConnectivitySnapshot().InitialCheckDone {
					t.Fatal("non-selected path unexpectedly completed its initial check")
				}
			}
		}
	}
}

func TestManualSelectorConcurrentSelectionAndConnectivity(t *testing.T) {
	paths := []*dialer.Dialer{newUncheckedDialer(t, "first"), newUncheckedDialer(t, "second")}
	g := newSelectorTestGroup(t, paths, emptyAnnotations(2), dialer.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Selector,
	}, nil)
	var workers sync.WaitGroup
	workers.Go(func() {
		for i := 0; i < 100; i++ {
			if err := g.SetSelection(paths[i%2].StatsID()); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Go(func() {
		for i := 0; i < 100; i++ {
			g.DialerChanged(paths[i%2], dialer.SelectionForceNone)
			if g.Selection() == "" || g.SelectedDialer(testNetworkType) == nil {
				t.Error("concurrent switch lost selection")
			}
			if _, err := g.Select(testNetworkType); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Wait()
}

func TestManualSelectorTrackingFollowsCommittedSelection(t *testing.T) {
	for _, trackAll := range []bool{false, true} {
		paths := []*dialer.Dialer{newCheckedDialer(t, "first"), newCheckedDialer(t, "second")}
		g := NewDialerGroup(paths[0].GlobalOption, t.Name(), GroupKindSelector, paths, emptyAnnotations(2), dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Selector, FixedIndexSet: true, TrackAll: trackAll,
		}, nil)
		t.Cleanup(func() { _ = g.Close() })
		assertTracking := func(first, second bool) {
			t.Helper()
			if paths[0].RuntimeStatus().CheckEnabled != first || paths[1].RuntimeStatus().CheckEnabled != second {
				t.Fatalf("tracking = %t/%t, want %t/%t", paths[0].RuntimeStatus().CheckEnabled, paths[1].RuntimeStatus().CheckEnabled, first, second)
			}
		}
		assertTracking(true, trackAll)
		if err := g.ChangeSelection(paths[1].StatsID(), func() error { return errors.New("save failed") }); err == nil {
			t.Fatal("failed selection unexpectedly committed")
		}
		assertTracking(true, trackAll)
		if err := g.SetSelection(paths[1].StatsID()); err != nil {
			t.Fatal(err)
		}
		assertTracking(trackAll, true)
		if err := g.SetSelection(""); err != nil {
			t.Fatal(err)
		}
		assertTracking(true, trackAll)
	}
}
