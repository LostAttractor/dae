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
			g.selector.selected[common.NetworkTCP4] = a
			g.selector.selected[common.NetworkUDP4] = a
			old, err := g.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil || old.Dialer != a {
				t.Fatalf("first selection = %v, %v", old.Dialer, err)
			}
			udp, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
			if err != nil {
				t.Fatal(err)
			}
			_ = a.Close()
			g.selector.selected[common.NetworkTCP4] = b
			current, err := g.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil || current.Dialer != b {
				t.Fatalf("new selection = %v, %v", current.Dialer, err)
			}
			if (old.Lease.AbortCause() != nil) != closeOld {
				t.Fatalf("previous connection generation: %v", old.Lease.AbortCause())
			}
			if current.Lease.AbortCause() != nil || udp.Lease.AbortCause() != nil {
				t.Fatal("reselection terminated new or unrelated-network connections")
			}
			if closeOld && old.Lease == current.Lease {
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
			fallback, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
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
			if (fallback.Lease.AbortCause() != nil) != closeFallback {
				t.Fatalf("fallback termination = %v", fallback.Lease.AbortCause())
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

func TestReloadOwnsLateSetupPolicyLeases(t *testing.T) {
	network := common.NetworkTCP4.NetworkType()
	old := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
	next := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
	last := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
	for _, g := range []*DialerGroup{old, next, last} {
		g.SetConnectionPolicy(true, true)
	}
	old.connections.networks[network.Index()].selected = "original"
	next.InheritConnections(old)
	last.InheritConnections(next)
	late := old.connectionLease(network, false)
	fallback := old.connectionLease(network, true)
	if late != last.connectionLease(network, false) || !late.Valid() {
		t.Fatal("late setup escaped current policy ownership")
	}
	last.closeReselectedConnections(network)
	last.connections.networks[network.Index()].selected = "replacement"
	if late.AbortCause() == nil || old.connectionLease(network, false).AbortCause() == nil {
		t.Fatal("reselection missed a predecessor's late setup")
	}
	if err := last.publishNetworkAvailable(network, true); err != nil {
		t.Fatal(err)
	}
	last.closeRecoveredConnections()
	if fallback.AbortCause() == nil || old.connectionLease(network, true).AbortCause() == nil {
		t.Fatal("recovery missed a predecessor's fallback")
	}
}

func TestReloadRetainsUnavailableManualChoice(t *testing.T) {
	for _, closeOld := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "close"}[closeOld], func(t *testing.T) {
			policy := dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector}
			old := newSelectorTestGroup(t, []*dialer.Dialer{newUncheckedDialer(t, "a")}, emptyAnnotations(1), policy, nil)
			old.SetConnectionPolicy(closeOld, false)
			network := common.NetworkTCP4.NetworkType()
			previous, err := old.SelectConnection(*network, true)
			if err != nil {
				t.Fatal(err)
			}
			next := newSelectorTestGroup(t, []*dialer.Dialer{newCheckedDialer(t, "a"), newCheckedDialer(t, "b")}, emptyAnnotations(2), policy, nil)
			next.SetConnectionPolicy(closeOld, false)
			selected := next.Dialers[1].StatsID()
			if err := next.SetSelection(selected); err != nil {
				t.Fatal(err)
			}
			next.InheritConnections(old)
			if next.Selection() != selected || next.connections.networks[network.Index()].selected != selected {
				t.Fatal("reload lost the unavailable manual choice")
			}
			if (previous.Lease.AbortCause() != nil) != closeOld || (old.connectionLease(network, false).AbortCause() != nil) != closeOld {
				t.Fatal("manual reload policy missed established or late predecessor connections")
			}
			fallback, err := next.SelectConnection(*network, true)
			if !errors.Is(err, ErrNoAliveDialer) || !fallback.Lease.Valid() {
				t.Fatalf("current unavailable selection lost its fallback lease: %v", err)
			}
		})
	}
}

func TestManualSelectionClosesPreviousGeneration(t *testing.T) {
	for _, closeOld := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "close"}[closeOld], func(t *testing.T) {
			a, b := newUncheckedDialer(t, "a"), newUncheckedDialer(t, "b")
			g := newSelectorTestGroup(t, []*dialer.Dialer{a, b}, emptyAnnotations(2), dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector}, nil)
			g.SetConnectionPolicy(closeOld, false)
			old, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
			if err != nil {
				t.Fatal(err)
			}
			if err := g.SetSelection(a.StatsID()); err != nil || old.Lease.AbortCause() != nil {
				t.Fatalf("unchanged selection closed connections: %v", err)
			}
			if err := g.SetSelection(b.StatsID()); err != nil {
				t.Fatal(err)
			}
			if (old.Lease.AbortCause() != nil) != closeOld {
				t.Fatalf("manual switch termination: %v", old.Lease.AbortCause())
			}
			current, err := g.SelectConnection(*common.NetworkUDP4.NetworkType(), true)
			if err != nil || current.Dialer != b || current.Lease.AbortCause() != nil {
				t.Fatalf("new manual selection: %v, %v", current.Dialer, err)
			}
		})
	}
}

func TestSelectionWaitsForManualChangeCommit(t *testing.T) {
	for _, commitErr := range []error{nil, errors.New("settings write failed")} {
		name := "commit"
		if commitErr != nil {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			a, b := newUncheckedDialer(t, "a"), newUncheckedDialer(t, "b")
			g := newSelectorTestGroup(t, []*dialer.Dialer{a, b}, emptyAnnotations(2), dialer.DialerSelectionPolicy{
				Policy: consts.DialerSelectionPolicy_Selector,
			}, nil)
			g.SetConnectionPolicy(true, false)
			old, err := g.SelectConnection(*testNetworkType, true)
			if err != nil {
				t.Fatal(err)
			}
			committing, release := make(chan struct{}), make(chan struct{})
			changed := make(chan error, 1)
			go func() {
				changed <- g.ChangeSelection(b.StatsID(), func() error {
					close(committing)
					<-release
					return commitErr
				})
			}()
			<-committing
			started := make(chan struct{})
			selected := make(chan ConnectionSelection, 1)
			go func() {
				close(started)
				selection, err := g.SelectConnection(*testNetworkType, true)
				if err != nil {
					t.Error(err)
				}
				selected <- selection
			}()
			<-started
			select {
			case <-selected:
				t.Error("selection escaped before settings committed")
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			if err := <-changed; !errors.Is(err, commitErr) {
				t.Fatalf("change = %v, want %v", err, commitErr)
			}
			if t.Failed() {
				return
			}
			current := <-selected
			if commitErr != nil {
				if current.Dialer != a || current.Lease != old.Lease || old.Lease.AbortCause() != nil {
					t.Fatal("rollback changed the existing path or connection generation")
				}
			} else if current.Dialer != b || current.Lease == old.Lease || old.Lease.AbortCause() == nil || current.Lease.AbortCause() != nil {
				t.Fatal("committed switch did not select a fresh connection generation")
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
				g.selectionIndex = policy.FixedIndex
				if g.selector != nil {
					for network := range g.selector.selected {
						g.selector.selected[network] = dials[policy.FixedIndex]
					}
				}
				g.SetConnectionPolicy(tc.closeOld, false)
				return g
			}
			old := makeGroup(false)
			previous, err := old.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil {
				t.Fatal(err)
			}
			_ = old.Close()
			next := makeGroup(tc.change)
			if tc.delayed {
				// No replacement exists yet; ownership must survive another
				// reload before a different ready path appears.
				pending := newSelectorTestGroup(t, nil, nil, dialer.DialerSelectionPolicy{}, nil)
				pending.SetConnectionPolicy(tc.closeOld, false)
				pending.InheritConnections(old)
				if previous.Lease.AbortCause() != nil {
					t.Fatal("closed without a replacement")
				}
				_ = pending.Close()
				old = pending
			}
			next.InheritConnections(old)
			if (previous.Lease.AbortCause() != nil) != (tc.closeOld && tc.change) {
				t.Fatalf("reload abort = %v", previous.Lease.AbortCause())
			}
			current, err := next.SelectConnection(*common.NetworkTCP4.NetworkType(), true)
			if err != nil || current.Dialer != next.Dialers[next.selectionPolicy.FixedIndex] || !current.Lease.Valid() {
				t.Fatalf("new selection = %v, %v", current.Dialer, err)
			}
			if (previous.Lease == current.Lease) == (tc.closeOld && tc.change) {
				t.Fatal("incorrect generation reuse")
			}
		})
	}
}
