// SPDX-License-Identifier: AGPL-3.0-only

package netproxy

import (
	"errors"
	"sync"
	"testing"
)

func TestPoolCapacityRequestsCoalesceAndOldErrorsStayRetired(t *testing.T) {
	p := NewPoolState(LayerH2)
	first := p.NewResource()
	p.Ready(first)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { p.RequestCapacity(nil) })
	}
	wg.Wait()
	second := p.NewResource()
	p.Ready(second)
	if s := p.Snapshot(); s.RecoveryRequired || s.UsableCapacity != 2 {
		t.Fatalf("capacity requests multiplied: %+v", s)
	}
	cause := errors.New("old connection")
	p.Failed(first, cause)
	failed := p.Snapshot()
	if !failed.Accepting || !failed.RecoveryRequired {
		t.Fatalf("healthy sibling lost: %+v", failed)
	}
	p.Failed(first, cause)
	if p.Snapshot().EpisodeID != failed.EpisodeID {
		t.Fatal("same failure counted twice")
	}
	replacement := p.NewResource()
	p.Ready(replacement)
	before := p.Snapshot()
	p.RefineFailure(first, WrapFailure(errors.New("late error"), Failure{Resource: first}))
	p.Remove(first)
	p.Ready(first)
	after := p.Snapshot()
	if after.Cause != nil || after.RecoveryRequired || after.EpisodeID != before.EpisodeID || after.UsableCapacity != 2 {
		t.Fatalf("old resource changed replacement: %+v", after)
	}
	p.Close()
	p.Ready(second)
	p.RequestCapacity(cause)
	if s := p.Snapshot(); s.State != SessionClosed || s.Accepting || s.RecoveryRequired {
		t.Fatalf("closed pool revived: %+v", s)
	}
}

func TestObservedPoolCapacityPreservesRecoveryContract(t *testing.T) {
	p := NewPoolState(LayerSMUX)
	initial := p.Snapshot()
	if initial.Accepting || !initial.RecoveryRequired || initial.RecoveryPhase != "queued" {
		t.Fatalf("empty pool does not request recovery: %+v", initial)
	}
	p.ObserveCapacity(PoolCapacity{UsableCapacity: 1, DesiredCapacity: 1})
	ready := p.Snapshot()
	root := errors.New("first carrier failure")
	for _, observation := range []PoolCapacity{
		{UsableCapacity: 1, DesiredCapacity: 2},
		{UsableCapacity: 1, DesiredCapacity: 2, Connecting: 1},
		{UsableCapacity: 1, DesiredCapacity: 2, EpisodeID: 1, Cause: root},
		{UsableCapacity: 1, DesiredCapacity: 2, EpisodeID: 2, Cause: errors.New("second carrier failure")},
	} {
		p.ObserveCapacity(observation)
		snapshot := p.Snapshot()
		if !snapshot.Accepting || !snapshot.RecoveryRequired || snapshot.UsableCapacity != 1 ||
			snapshot.Resource != ready.Resource || snapshot.ReadinessVersion != ready.ReadinessVersion || snapshot.EpisodeID != observation.EpisodeID {
			t.Fatalf("background replenishment changed healthy readiness: %+v", snapshot)
		}
		if observation.Connecting != 0 && snapshot.RecoveryPhase != "connecting" {
			t.Fatal("connecting phase was hidden by a healthy sibling")
		}
		if observation.EpisodeID != 0 && !errors.Is(snapshot.Cause, root) {
			t.Fatal("later failure replaced the pending recovery cause")
		}
		p.ObserveCapacity(observation)
		if p.Snapshot().Seq != snapshot.Seq {
			t.Fatal("unchanged capacity published another event")
		}
	}
	p.ObserveCapacity(PoolCapacity{UsableCapacity: 2, DesiredCapacity: 2, EpisodeID: 2})
	restored := p.Snapshot()
	if restored.Cause != nil || restored.RecoveryRequired || restored.RecoveryPhase != "ready" || restored.ReadinessVersion != ready.ReadinessVersion {
		t.Fatalf("replenishment did not clear recovery metadata: %+v", restored)
	}
	p.ObserveCapacity(PoolCapacity{UsableCapacity: 2, DesiredCapacity: 2, EpisodeID: 1, Cause: root})
	if p.Snapshot().Seq != restored.Seq {
		t.Fatal("late failure metadata revived a completed recovery")
	}
	p.ObserveCapacity(PoolCapacity{DesiredCapacity: 2, EpisodeID: 3, Cause: root})
	lost := p.Snapshot()
	if lost.Accepting || !lost.RecoveryRequired || lost.State != SessionDisconnected || lost.ReadinessVersion <= ready.ReadinessVersion {
		t.Fatalf("last-member failure did not close admission: %+v", lost)
	}
	p.Close()
	closed := p.Snapshot()
	p.ObserveCapacity(PoolCapacity{UsableCapacity: 3, DesiredCapacity: 3, EpisodeID: 4})
	if p.Snapshot().Seq != closed.Seq || closed.State != SessionClosed || closed.Accepting || closed.RecoveryRequired || closed.UsableCapacity != 0 || closed.RecoveryPhase != "stopped" {
		t.Fatalf("closed pool revived or retained capacity: %+v", p.Snapshot())
	}
}

type poolSliceError []string

func (e poolSliceError) Error() string { return "protocol error" }

func TestPoolCapacityAcceptsNonComparableErrors(t *testing.T) {
	p := NewPoolState(LayerAnyTLS)
	observation := PoolCapacity{DesiredCapacity: 1, Cause: poolSliceError{"failure"}}
	p.ObserveCapacity(observation)
	p.ObserveCapacity(observation)
	if p.Snapshot().Cause == nil {
		t.Fatal("protocol cause was discarded")
	}
}
