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
