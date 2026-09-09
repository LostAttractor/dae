package outbound

import (
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestReselectionClosesOnlyPreviousNetworkGeneration(t *testing.T) {
	for _, closeOld := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "close"}[closeOld], func(t *testing.T) {
			a, b := newUncheckedDialer(t, "a"), newUncheckedDialer(t, "b")
			annotations := emptyAnnotations(2)
			annotations[1].AddLatency = time.Second
			g := newSelectorTestGroup(t, []*dialer.Dialer{a, b}, annotations,
				dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, nil)
			g.SetConnectionPolicy(closeOld, false)
			selected, _, _, old, err := g.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil || selected != a {
				t.Fatalf("first selection = %v, %v", selected, err)
			}
			_, _, _, udp, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
			if err != nil {
				t.Fatal(err)
			}
			_ = a.Close()
			selected, _, _, current, err := g.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil || selected != b {
				t.Fatalf("new selection = %v, %v", selected, err)
			}
			if (old.AbortCause() != nil) != closeOld {
				t.Fatalf("previous connection generation: %v", old.AbortCause())
			}
			if current.AbortCause() != nil || udp.AbortCause() != nil {
				t.Fatal("reselection terminated new or unrelated-network connections")
			}
			if closeOld && old == current {
				t.Fatal("new setup reused an aborted generation")
			}
		})
	}
}

func TestFallbackRecoveryOnlyClosesOriginalGroupAndNetwork(t *testing.T) {
	for _, closeFallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "close"}[closeFallback], func(t *testing.T) {
			a := newCheckedDialer(t, "a")
			g := newSelectorTestGroup(t, []*dialer.Dialer{a}, emptyAnnotations(1), dialer.DialerSelectionPolicy{}, nil)
			g.SetConnectionPolicy(true, closeFallback)
			_, _, _, fallback, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
			if !errors.Is(err, ErrNoAliveDialer) {
				t.Fatalf("selection = %v", err)
			}
			otherNetwork := g.connectionLease(common.NetworkUDP6.NetworkType(), true)
			regular := g.connectionLease(common.NetworkUDP4.NetworkType(), false)
			other := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
			other.SetConnectionPolicy(true, true)
			otherGroup := other.connectionLease(common.NetworkUDP4.NetworkType(), true)
			if err := g.publishNetworkAvailable(common.NetworkUDP4.NetworkType(), true); err != nil {
				t.Fatal(err)
			}
			g.closeRecoveredConnections()
			if (fallback.AbortCause() != nil) != closeFallback {
				t.Fatalf("fallback termination = %v", fallback.AbortCause())
			}
			if regular.AbortCause() != nil || otherNetwork.AbortCause() != nil || otherGroup.AbortCause() != nil {
				t.Fatal("fallback recovery affected unrelated connections")
			}
		})
	}
}

func TestReloadKeepsFallbackPolicyOwnership(t *testing.T) {
	old := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
	old.SetConnectionPolicy(false, false)
	fallback := old.connectionLease(common.NetworkUDP4.NetworkType(), true)
	regular := old.connectionLease(common.NetworkUDP4.NetworkType(), false)
	_ = old.Close()
	next := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
	next.SetConnectionPolicy(false, true)
	if err := next.publishNetworkAvailable(common.NetworkUDP4.NetworkType(), true); err != nil {
		t.Fatal(err)
	}
	next.InheritConnections(old)
	if fallback.AbortCause() == nil || regular.AbortCause() != nil {
		t.Fatal("reload lost the original fallback generation or closed regular connections")
	}
}

func TestManualSelectionClosesPreviousGeneration(t *testing.T) {
	for _, closeOld := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "close"}[closeOld], func(t *testing.T) {
			a, b := newUncheckedDialer(t, "a"), newUncheckedDialer(t, "b")
			g := newSelectorTestGroup(t, []*dialer.Dialer{a, b}, emptyAnnotations(2), dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector}, nil)
			g.SetConnectionPolicy(closeOld, false)
			_, _, _, old, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
			if err != nil {
				t.Fatal(err)
			}
			if err := g.SetSelection(a.StatsID()); err != nil || old.AbortCause() != nil {
				t.Fatalf("unchanged selection closed connections: %v", err)
			}
			if err := g.SetSelection(b.StatsID()); err != nil {
				t.Fatal(err)
			}
			if (old.AbortCause() != nil) != closeOld {
				t.Fatalf("manual switch termination: %v", old.AbortCause())
			}
			selected, _, _, current, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
			if err != nil || selected != b || current.AbortCause() != nil {
				t.Fatalf("new manual selection: %v, %v", selected, err)
			}
		})
	}
}

func TestReloadReselectionConnectionPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		policy                    consts.DialerSelectionPolicy
		closeOld, change, delayed bool
	}{
		{"changed", consts.DialerSelectionPolicy_MinLastLatency, true, true, false},
		{"same path", consts.DialerSelectionPolicy_MinLastLatency, true, false, false},
		{"keep", consts.DialerSelectionPolicy_MinLastLatency, false, true, false},
		{"delayed selection", consts.DialerSelectionPolicy_MinLastLatency, true, true, true},
		{"manual changed", consts.DialerSelectionPolicy_Selector, true, true, false},
		{"manual same path", consts.DialerSelectionPolicy_Selector, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makeGroup := func(selectB bool) *DialerGroup {
				dials := make([]*dialer.Dialer, 2)
				for i, name := range []string{"a", "b"} {
					dials[i] = dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: fakeDialer{}}), &dialer.GlobalOption{}, &dialer.Property{Name: name, Link: "test://" + name}, false, "")
				}
				policy := dialer.DialerSelectionPolicy{Policy: tc.policy}
				annotations := emptyAnnotations(2)
				annotations[1].AddLatency = time.Second
				if selectB {
					annotations[0].AddLatency, annotations[1].AddLatency = time.Second, 0
					policy.FixedIndex = 1
				}
				g := newSelectorTestGroup(t, dials, annotations, policy, nil)
				g.selectionIndex.Store(int64(policy.FixedIndex))
				g.SetConnectionPolicy(tc.closeOld, false)
				return g
			}
			old := makeGroup(false)
			_, _, _, lease, err := old.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil {
				t.Fatal(err)
			}
			_ = old.Close()
			next := makeGroup(tc.change)
			if next.selector != nil {
				next.selector.Refresh(nil, dialer.SelectionForceNone)
			}
			if tc.delayed {
				// No replacement exists yet; ownership must survive another
				// reload before a different ready path appears.
				pending := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
				pending.SetConnectionPolicy(tc.closeOld, false)
				pending.InheritConnections(old)
				if lease.AbortCause() != nil {
					t.Fatal("closed without a replacement")
				}
				_ = pending.Close()
				old = pending
			}
			next.InheritConnections(old)
			if (lease.AbortCause() != nil) != (tc.closeOld && tc.change) {
				t.Fatalf("reload abort = %v", lease.AbortCause())
			}
			chosen, _, _, current, err := next.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil || chosen != next.Dialers[next.selectionPolicy.FixedIndex] || !current.Valid() {
				t.Fatalf("new selection = %v, %v", chosen, err)
			}
			if (lease == current) == (tc.closeOld && tc.change) {
				t.Fatal("incorrect generation reuse")
			}
		})
	}
}
