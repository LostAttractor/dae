package netproxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type leaseDependency struct{ lease *Lease }

func (d leaseDependency) DependencyLease() *Lease { return d.lease }

func TestLeaseStreamInvalidationOnlyAffectsActualSubtree(t *testing.T) {
	parent := NewLease(NewResourceRef())
	streamA, streamB := parent.NewStream(), parent.NewStream()
	childA, childB := NewLease(NewResourceRef(), streamA), NewLease(NewResourceRef(), streamB)
	cause := errors.New("RESET_STREAM")
	streamA.Invalidate(cause)
	if streamA.Valid() || childA.Valid() {
		t.Fatal("dependent child still accepts allocations")
	}
	if !parent.Valid() || !streamB.Valid() || !childB.Valid() {
		t.Fatal("unrelated sibling invalidated")
	}
	if !errors.Is(childA.Cause(), cause) {
		t.Fatal("dependency root cause lost")
	}
	parent.Invalidate(errors.New("connection reset"))
	if streamB.Valid() || childB.Valid() {
		t.Fatal("connection failure did not invalidate all remaining dependents")
	}
}

func TestLeaseAbortFollowsActualDependencies(t *testing.T) {
	parent := NewLease(NewResourceRef())
	failed, healthy := parent.NewStream(), parent.NewStream()
	resource := NewLease(NewResourceRef(), failed)
	stream := resource.NewStream()
	cause := errors.New("owner confirmed unusable resource")
	if !failed.Abort(cause) {
		t.Fatal("first abort rejected")
	}
	lateStream := resource.NewStream()
	for _, lease := range []*Lease{failed, resource, stream, lateStream} {
		if lease.Valid() || !errors.Is(lease.AbortCause(), cause) {
			t.Fatalf("dependent lease missed abort: valid=%v cause=%v", lease.Valid(), lease.AbortCause())
		}
		select {
		case <-lease.Done():
		default:
			t.Fatal("dependent consumer was not notified")
		}
	}
	for _, lease := range []*Lease{parent, healthy} {
		if !lease.Valid() || lease.AbortCause() != nil {
			t.Fatal("abort crossed the failed dependency subtree")
		}
	}
	laterCause := errors.New("parent failed later")
	parent.Abort(laterCause)
	if !errors.Is(healthy.AbortCause(), laterCause) || !errors.Is(stream.AbortCause(), cause) {
		t.Fatal("parent abort missed remaining consumer or rewrote earlier cause")
	}
}

func TestLeaseInvalidationDoesNotBecomeAbort(t *testing.T) {
	parent := NewLease(NewResourceRef())
	stream := parent.NewStream()
	// An error's metadata never substitutes for the owner's explicit action.
	cause := WrapFailure(errors.New("diagnostic only"), Failure{Scope: ScopeSharedResource})
	if !parent.Invalidate(cause) || parent.Abort(errors.New("late abort")) {
		t.Fatal("first invalidation did not remain authoritative")
	}
	for _, lease := range []*Lease{parent, stream, parent.NewStream()} {
		if lease.Valid() || lease.AbortCause() != nil || !errors.Is(lease.Cause(), cause) {
			t.Fatalf("invalidation changed action or cause: valid=%v abort=%v cause=%v", lease.Valid(), lease.AbortCause(), lease.Cause())
		}
	}

	parent = NewLease(NewResourceRef())
	stream = parent.NewStream()
	stream.Invalidate(nil)
	parent.Abort(errors.New("failure after stream closed"))
	if stream.AbortCause() != nil {
		t.Fatal("parent aborted an already closed stream")
	}
}

func TestLeaseAbortNilCauseAndNilLease(t *testing.T) {
	var absent *Lease
	if absent.Abort(nil) || absent.Invalidate(nil) || absent.AbortCause() != nil || absent.Done() != nil {
		t.Fatal("absent dependency has a lifecycle signal")
	}
	lease := NewLease(NewResourceRef())
	if !lease.Abort(nil) || !errors.Is(lease.AbortCause(), ErrDependencyInvalid) {
		t.Fatal("abort without a diagnostic lost its termination signal")
	}
	if lease.Invalidate(errors.New("cleanup")) || !errors.Is(lease.AbortCause(), ErrDependencyInvalid) {
		t.Fatal("cleanup replaced the owner's abort")
	}
}

func TestSingleSessionRejectsDependencyInvalidatedDuringEstablish(t *testing.T) {
	parent := NewLease(NewResourceRef())
	started, release := make(chan struct{}), make(chan struct{})
	var closed atomic.Int32
	session := NewSingleSession(SingleSessionConfig[int]{
		Establish: func(ctx context.Context) (int, error) {
			CaptureDependency(ctx, leaseDependency{parent})
			close(started)
			<-release
			return 1, nil
		},
		Close: func(int) error { closed.Add(1); return nil },
	})
	defer session.Close()
	result := make(chan error, 1)
	go func() { result <- session.Connect(context.Background()) }()
	<-started
	parent.Invalidate(errors.New("parent stream reset"))
	close(release)
	if err := <-result; !errors.Is(err, ErrDependencyInvalid) {
		t.Fatalf("Connect error=%v", err)
	}
	if _, err := session.Current(); err == nil {
		t.Fatal("installed resource with dead dependency")
	}
	if closed.Load() != 1 {
		t.Fatalf("cleanup count=%d", closed.Load())
	}
}

func TestDependencyGateAndSnapshotDoNotWaitForObserver(t *testing.T) {
	parent := NewLease(NewResourceRef())
	closed := make(chan struct{})
	session := NewSingleSession(SingleSessionConfig[int]{
		Establish: func(ctx context.Context) (int, error) { CaptureDependency(ctx, leaseDependency{parent}); return 1, nil },
		Close:     func(int) error { close(closed); return nil },
	})
	defer session.Close()
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	parent.Invalidate(errors.New("parent connection lost"))
	if _, err := session.Current(); err == nil {
		t.Fatal("allocation crossed invalid dependency")
	}
	if session.Snapshot().Accepting {
		t.Fatal("snapshot accepts invalid dependency")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("observer failed to clean invalid child after Snapshot")
	}
}

func TestResourceGenerationAndCleanupPhase(t *testing.T) {
	closing, release := make(chan struct{}), make(chan struct{})
	var counter int
	session := NewSingleSession(SingleSessionConfig[int]{
		Establish: func(context.Context) (int, error) { counter++; return counter, nil },
		Close: func(resource int) error {
			if resource == 1 {
				close(closing)
				<-release
			}
			return nil
		},
	})
	defer session.Close()
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _ := session.CurrentHandle()
	disconnected := make(chan bool, 1)
	go func() { disconnected <- first.Abort(errors.New("lost")) }()
	<-closing
	snapshot := session.Snapshot()
	if snapshot.Accepting || snapshot.RecoveryPhase != "cleanup" {
		t.Fatalf("cleanup snapshot=%+v", snapshot)
	}
	connected := make(chan error, 1)
	go func() { connected <- session.Connect(context.Background()) }()
	select {
	case err := <-connected:
		t.Fatalf("replacement crossed cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-disconnected
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	second, _ := session.CurrentHandle()
	if second.Ref().Generation != first.Ref().Generation+1 || second.Ref().ResourceID != first.Ref().ResourceID {
		t.Fatalf("resource refs = %+v / %+v", first.Ref(), second.Ref())
	}
	ready := session.Snapshot()
	if first.Abort(errors.New("late")) {
		t.Fatal("stale generation disconnected replacement")
	}
	if session.Snapshot() != ready {
		t.Fatal("stale generation rewrote current status")
	}
}

func TestStaleObserverCannotRewriteReplacement(t *testing.T) {
	session := NewSingleSession(SingleSessionConfig[int]{Establish: func(context.Context) (int, error) { return 1, nil }})
	defer session.Close()
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _ := session.CurrentHandle()
	if !first.Transition(SessionDisconnected, errors.New("first channel lost")) {
		t.Fatal("current handle rejected")
	}
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ready := session.Snapshot()
	if first.Transition(SessionDisconnected, errors.New("late old observer")) {
		t.Fatal("stale observer accepted after resource replacement")
	}
	if session.Snapshot() != ready {
		t.Fatal("stale observer changed replacement status")
	}
}

func TestAbortReturnsBeforeBlockingCleanup(t *testing.T) {
	closing, release := make(chan struct{}), make(chan struct{})
	session := NewSingleSession(SingleSessionConfig[int]{
		Establish: func(context.Context) (int, error) { return 1, nil },
		Close:     func(int) error { close(closing); <-release; return nil },
	})
	defer session.Close()
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle, _ := session.CurrentHandle()
	returned := make(chan bool, 1)
	go func() { returned <- handle.Abort(errors.New("TCP reset")) }()
	select {
	case ok := <-returned:
		if !ok {
			t.Fatal("current invalidation rejected")
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("data-plane failure blocked on resource cleanup")
	}
	<-closing
	if _, err := session.Current(); err == nil {
		t.Fatal("allocation crossed cleanup gate")
	}
	if snapshot := session.Snapshot(); snapshot.RecoveryPhase != "cleanup" || snapshot.Accepting {
		t.Fatalf("incorrect cleanup snapshot: %+v", snapshot)
	}
	close(release)
}

func TestSessionGroupPreservesDegradedPoolFactsWithoutChangingReadiness(t *testing.T) {
	inner, outer := newTestSession(), newTestSession()
	if err := inner.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := outer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	in := inner.Snapshot()
	in.Resource = NewResourceRef()
	in.Layer = LayerSMUX
	in.UsableCapacity = 3
	in.RecoveryExecutor = RecoveryDaemon
	inner.state.Publish(in)
	out := outer.Snapshot()
	out.Resource = NewResourceRef()
	out.Layer = LayerGRPC
	out.UsableCapacity = 2
	out.RecoveryExecutor = RecoveryLibraryManaged
	outer.state.Publish(out)
	group := NewSessionGroup(inner, outer)
	defer group.Stop()
	ready := group.Snapshot()
	degraded := inner.Snapshot()
	degraded.UsableCapacity = 1
	degraded.Cause = errors.New("one pool slot lost")
	degraded.RecoveryRequired = true
	inner.state.Publish(degraded)
	actual := group.Snapshot()
	if !actual.Accepting || actual.UsableCapacity != 1 || actual.Resource != degraded.Resource || actual.Cause != degraded.Cause || !actual.RecoveryRequired {
		t.Fatalf("lost pool facts: %+v", actual)
	}
	if actual.ReadinessVersion != ready.ReadinessVersion {
		t.Fatalf("diagnostic resource switch changed readiness: %d -> %d", ready.ReadinessVersion, actual.ReadinessVersion)
	}
	if actual.RecoveryExecutor != RecoveryDaemon {
		t.Fatal("mixed chain assigned to library-only recovery")
	}
	blocked := outer.Snapshot()
	blocked.Accepting = false
	outer.state.Publish(blocked)
	if actual := group.Snapshot(); actual.Accepting || actual.UsableCapacity != 0 || actual.RecoveryExecutor != RecoveryLibraryManaged {
		t.Fatalf("blocked library channel did not own chain recovery: %+v", actual)
	}
	blocked.Accepting = true
	outer.state.Publish(blocked)
	if actual := group.Snapshot(); !actual.Accepting || actual.RecoveryExecutor != RecoveryDaemon || !actual.RecoveryRequired {
		t.Fatalf("ready library channel did not return replenishment to the daemon: %+v", actual)
	}
}

func TestSessionGroupKeepsLogicalPublisherEpisodeDomains(t *testing.T) {
	first, second := newTestSession(), newTestSession()
	_ = first.Connect(context.Background())
	_ = second.Connect(context.Background())
	firstEvent, secondEvent := first.Snapshot(), second.Snapshot()
	if firstEvent.PublisherID == 0 || firstEvent.PublisherID == secondEvent.PublisherID {
		t.Fatal("logical publishers are not distinct")
	}
	group := NewSessionGroup(first, second)
	defer group.Stop()
	ready := group.Snapshot()
	firstEvent.Cause = errors.New("logical channel A failure")
	firstEvent.EpisodeID = 7
	firstEvent.Layer = LayerGRPC
	first.state.Publish(firstEvent)
	a := group.Snapshot()
	secondEvent.Cause = errors.New("logical channel B failure")
	secondEvent.EpisodeID = 2
	secondEvent.Layer = LayerGRPC
	second.state.Publish(secondEvent)
	firstEvent.Cause = nil
	first.state.Publish(firstEvent)
	b := group.Snapshot()
	firstEvent.Cause = errors.New("repeated channel A diagnostic")
	first.state.Publish(firstEvent)
	again := group.Snapshot()
	if a.PublisherID != firstEvent.PublisherID || a.EpisodeID != 7 || b.PublisherID != secondEvent.PublisherID || b.EpisodeID != 2 || again.PublisherID != a.PublisherID || again.EpisodeID != a.EpisodeID {
		t.Fatalf("publisher/episode domains crossed: A=%+v B=%+v A=%+v", a, b, again)
	}
	if a.Resource != (ResourceRef{}) || b.Resource != (ResourceRef{}) {
		t.Fatal("logical publishers invented physical transport identity")
	}
	if a.ReadinessVersion != ready.ReadinessVersion || b.ReadinessVersion != ready.ReadinessVersion || again.ReadinessVersion != ready.ReadinessVersion {
		t.Fatal("publisher diagnostic switch changed readiness")
	}
}
