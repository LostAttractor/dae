package netproxy

import (
	"context"
	"errors"
	"net"
	"sync"
)

// SingleSession owns one shared transport resource. Callbacks must honor
// cancellation and must not synchronously call Connect or Close. Observe may
// use its handle to publish transitions or abort its resource.
type SingleSession[T any] struct {
	config SingleSessionConfig[T]

	operation chan struct{}
	state     *StateBroadcaster
	ctx       context.Context
	cancel    context.CancelFunc

	mu         sync.RWMutex
	current    *SingleSessionHandle[T]
	observers  sync.WaitGroup
	cleanupErr error
	closeOnce  sync.Once
	ref        ResourceRef
	// A reconnect attempt may pass through Connecting with no cause before
	// reporting failure. Keep its accident open until the resource is ready.
	failureEpisode bool
}

// SingleSessionHandle is the identity of one installed resource. A stale
// handle can no longer publish state or disconnect a replacement resource.
type SingleSessionHandle[T any] struct {
	owner         *SingleSession[T]
	resource      T
	cancel        context.CancelFunc
	ref           ResourceRef
	lease         *Lease
	disconnecting bool
}

func (h *SingleSessionHandle[T]) Resource() T      { return h.resource }
func (h *SingleSessionHandle[T]) Ref() ResourceRef { return h.ref }
func (h *SingleSessionHandle[T]) Lease() *Lease {
	h.owner.mu.RLock()
	defer h.owner.mu.RUnlock()
	return h.lease
}
func (h *SingleSessionHandle[T]) NewStreamLease() *Lease { return h.Lease().NewStream() }

func (h *SingleSessionHandle[T]) Transition(state SessionState, cause error) bool {
	if h == nil || state > SessionConnected {
		return false
	}
	s := h.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.current != h || h.disconnecting {
		return false
	}
	if state != SessionConnected {
		h.lease.Invalidate(cause)
	}
	if state == SessionConnected && !h.renewLeaseLocked() {
		return false
	}
	s.transitionLocked(state, cause)
	return true
}

// A retained logical channel needs a new lease when it becomes ready again.
// The owner lock protects replacement; parent gates remain authoritative.
func (h *SingleSessionHandle[T]) renewLeaseLocked() bool {
	if h.lease.Valid() {
		return true
	}
	lease := NewLease(h.ref, h.lease.parents...)
	if !lease.Valid() {
		return false
	}
	h.lease = lease
	return true
}

// Abort revokes this resource and its dependents before returning. Cleanup runs
// asynchronously; Connect waits for it before replacement and Close waits for it
// before returning. Ordinary shutdown uses SingleSession.Close, not Abort.
func (h *SingleSessionHandle[T]) Abort(cause error) bool {
	s := h.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.current != h || h.disconnecting {
		return false
	}
	h.disconnecting = true
	h.lease.Abort(cause)
	s.transitionLocked(SessionDisconnected, cause)
	s.phaseLocked("cleanup", "")
	s.observers.Add(1)
	go h.cleanupDisconnected()
	return true
}

func (h *SingleSessionHandle[T]) cleanupDisconnected() {
	s := h.owner
	defer s.observers.Done()
	select {
	case s.operation <- struct{}{}:
		defer func() { <-s.operation }()
	case <-s.ctx.Done():
		return
	}
	s.mu.Lock()
	if s.ctx.Err() != nil || s.current != h {
		s.mu.Unlock()
		return
	}
	resource := s.detachLocked()
	s.mu.Unlock()
	s.recordCloseError(s.closeHandle(resource))
	s.mu.Lock()
	if s.ctx.Err() == nil && s.current == nil {
		s.phaseLocked("queued", "")
	}
	s.mu.Unlock()
}

type SingleSessionConfig[T any] struct {
	Layer FailureLayer
	// RecoveryExecutor applies to a retained resource. Establishing or replacing
	// a resource always requires a daemon Connect attempt.
	RecoveryExecutor RecoveryExecutor
	// LogicalChannel reports no physical resource identity: library-owned
	// transports may be replaced without an observable one-to-one channel mapping.
	LogicalChannel bool
	Establish      func(context.Context) (T, error)
	// IsConnected optionally verifies a retained resource before Connect's
	// connected fast path. It must not block or call lifecycle methods.
	IsConnected func(T) bool
	// Recover optionally reconnects a retained but disconnected resource and
	// requires IsConnected to verify the result.
	// Returning replace asks SingleSession to close it and establish a new one.
	// Otherwise the resource is retained, including when an error is returned.
	Recover func(context.Context, T) (replace bool, err error)
	Observe func(context.Context, *SingleSessionHandle[T])
	Close   func(T) error
}

func NewSingleSession[T any](config SingleSessionConfig[T]) *SingleSession[T] {
	if config.Recover != nil && config.IsConnected == nil {
		panic("SingleSession Recover requires IsConnected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &SingleSession[T]{
		ref:       NewResourceRef(),
		config:    config,
		operation: make(chan struct{}, 1),
		state:     NewStateBroadcaster(SessionDisconnected),
		ctx:       ctx,
		cancel:    cancel,
	}
	s.ref.Generation = 0
	if config.RecoveryExecutor == "" {
		s.config.RecoveryExecutor = RecoveryDaemon
	}
	initial := s.state.current
	initial.Layer, initial.RecoveryExecutor = s.config.Layer, RecoveryDaemon
	s.state.current = initial
	return s
}

func (s *SingleSession[T]) transitionLocked(state SessionState, cause error) {
	event := s.state.Snapshot()
	ref := s.ref
	if s.config.LogicalChannel {
		ref = ResourceRef{}
	}
	executor := s.config.RecoveryExecutor
	if s.current == nil || s.current.disconnecting {
		executor = RecoveryDaemon
	}
	accepting := state == SessionConnected
	newFailure := cause != nil && !accepting && state != SessionClosed && !s.failureEpisode
	if event.State == state && event.Resource == ref && event.Accepting == accepting && event.RecoveryExecutor == executor && !newFailure {
		return
	}
	if newFailure {
		event.EpisodeID++
		s.failureEpisode = true
	} else if accepting && cause == nil {
		s.failureEpisode = false
	}
	event.State, event.Cause, event.Resource = state, cause, ref
	event.BlockedBy = ""
	switch state {
	case SessionConnected:
		event.RecoveryPhase = "ready"
	case SessionConnecting:
		event.RecoveryPhase = "connecting"
	case SessionClosed:
		event.RecoveryPhase = "stopped"
	case SessionDisconnected:
		event.RecoveryPhase = "queued"
		if executor == RecoveryLibraryManaged {
			event.RecoveryPhase = "connecting"
		}
	}
	event.Accepting, event.UsableCapacity = accepting, boolCapacity(accepting)
	event.Layer, event.RecoveryExecutor = s.config.Layer, executor
	s.state.Publish(event)
}
func (s *SingleSession[T]) phaseLocked(phase, blockedBy string) {
	event := s.state.Snapshot()
	if event.RecoveryPhase == phase && event.BlockedBy == blockedBy {
		return
	}
	event.RecoveryPhase, event.BlockedBy = phase, blockedBy
	s.state.Publish(event)
}
func (s *SingleSession[T]) Snapshot() StateEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Reconcile a revoked dependency before reporting admission readiness.
	// Publishing here keeps Snapshot and WatchState on the same revision;
	// physical cleanup still belongs to the dependency observer.
	if s.current != nil && !s.current.lease.Valid() && s.state.Snapshot().State == SessionConnected {
		cause := s.current.lease.Cause()
		fact := ClassifyFailure(cause)
		fact.Resource, fact.Scope = s.current.Ref(), ScopeSharedResource
		if fact.Layer == LayerUnknown || fact.Layer == "" {
			fact.Layer = s.config.Layer
		}
		s.transitionLocked(SessionDisconnected, WrapFailure(cause, fact))
		s.phaseLocked("cleanup", "")
	}
	return s.state.Snapshot()
}

func (s *SingleSession[T]) WatchState(ctx context.Context) <-chan StateEvent {
	return s.state.WatchState(ctx)
}

func (s *SingleSession[T]) Connect(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.operation <- struct{}{}:
		defer func() { <-s.operation }()
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	connectCtx, cancel := NewDialTimeoutContextFrom(ctx)
	defer cancel()
	stopClose := context.AfterFunc(s.ctx, cancel)
	defer stopClose()
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	current := s.current
	connected := current != nil && s.state.Snapshot().State == SessionConnected
	if current != nil && s.config.IsConnected != nil {
		connected = s.config.IsConnected(current.resource)
	}
	if current != nil && !current.lease.Valid() {
		connected = false
	}
	if connected {
		if err := connectCtx.Err(); err != nil {
			s.mu.Unlock()
			return err
		}
		s.transitionLocked(SessionConnected, nil)
		s.mu.Unlock()
		return nil
	}
	canRecover := current != nil && !current.disconnecting && s.config.Recover != nil
	s.mu.Unlock()

	if canRecover {
		return s.recoverCurrent(connectCtx, current)
	}

	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	current = s.detachLocked()
	s.transitionLocked(SessionConnecting, nil)
	if current != nil {
		s.phaseLocked("cleanup", "")
	}
	s.mu.Unlock()
	s.recordCloseError(s.closeHandle(current))
	return s.establishAndInstall(connectCtx)
}

func (s *SingleSession[T]) recoverCurrent(ctx context.Context, current *SingleSessionHandle[T]) error {
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if current.disconnecting {
		cause := current.lease.Cause()
		s.mu.Unlock()
		return cause
	}
	s.transitionLocked(SessionConnecting, nil)
	s.mu.Unlock()
	replace, err := s.config.Recover(ctx, current.resource)
	operationErr := ctx.Err()
	if operationErr != nil && !errors.Is(err, operationErr) {
		err = errors.Join(err, operationErr)
	}

	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if current.disconnecting {
		cause := current.lease.Cause()
		s.mu.Unlock()
		return cause
	}
	if !replace {
		if operationErr != nil {
			s.transitionLocked(SessionDisconnected, err)
			s.mu.Unlock()
			return err
		}
		if s.config.IsConnected(current.resource) {
			if !current.renewLeaseLocked() {
				s.transitionLocked(SessionDisconnected, ErrDependencyInvalid)
				s.mu.Unlock()
				return ErrDependencyInvalid
			}
			s.transitionLocked(SessionConnected, nil)
			s.mu.Unlock()
			return nil
		}
		if err == nil {
			err = s.state.Snapshot().Cause
			if err == nil {
				err = ErrNotConnected
			}
		}
		s.transitionLocked(SessionDisconnected, err)
		s.mu.Unlock()
		return err
	}

	resource := s.detachLocked()
	if err != nil {
		s.transitionLocked(SessionDisconnected, err)
	} else {
		s.transitionLocked(SessionConnecting, nil)
	}
	s.mu.Unlock()
	s.recordCloseError(s.closeHandle(resource))
	if err != nil {
		return err
	}
	return s.establishAndInstall(ctx)
}

func (s *SingleSession[T]) establishAndInstall(ctx context.Context) error {
	s.mu.Lock()
	s.phaseLocked("connecting", "")
	s.mu.Unlock()
	establishCtx, dependencies := collectDependencies(ctx)
	resource, err := s.config.Establish(establishCtx)
	s.mu.Lock()
	if err != nil {
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			return net.ErrClosed
		}
		// Cancellation bounds the operation; it must not erase its diagnosis.
		if operationErr := ctx.Err(); operationErr != nil && !errors.Is(err, operationErr) {
			err = errors.Join(err, operationErr)
		}
		s.transitionLocked(SessionDisconnected, err)
		s.mu.Unlock()
		return err
	}
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return net.ErrClosed
	}
	if operationErr := ctx.Err(); operationErr != nil {
		s.transitionLocked(SessionDisconnected, operationErr)
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return operationErr
	}
	parents := dependencies.snapshot()
	s.ref.Generation++
	ref := s.ref
	if s.config.LogicalChannel {
		ref = ResourceRef{}
	}
	lease := NewLease(ref, parents...)
	if !lease.Valid() {
		cause := WrapFailure(ErrDependencyInvalid, Failure{Scope: ScopeSharedResource, Layer: s.config.Layer, Phase: OpHandshake})
		s.transitionLocked(SessionDisconnected, cause)
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return cause
	}
	observerCtx, observerCancel := context.WithCancel(context.Background())
	handle := &SingleSessionHandle[T]{owner: s, resource: resource, ref: ref, lease: lease, cancel: observerCancel}
	s.current = handle
	s.transitionLocked(SessionConnected, nil)
	if s.config.Observe != nil {
		s.observers.Add(1)
		go func() { defer s.observers.Done(); s.config.Observe(observerCtx, handle) }()
	}
	for _, parent := range parents {
		s.observers.Add(1)
		go func(parent *Lease) {
			defer s.observers.Done()
			select {
			case <-observerCtx.Done():
				return
			case <-parent.Done():
			}
			fact := ClassifyFailure(parent.Cause())
			fact.Resource, fact.Scope = handle.Ref(), ScopeSharedResource
			if fact.Layer == LayerUnknown || fact.Layer == "" {
				fact.Layer = s.config.Layer
			}
			handle.Abort(WrapFailure(parent.Cause(), fact))
		}(parent)
	}
	s.mu.Unlock()
	return nil
}

func (s *SingleSession[T]) CurrentHandle() (*SingleSessionHandle[T], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if s.current == nil || !s.current.lease.Valid() || s.state.Snapshot().State != SessionConnected {
		return nil, ErrNotConnected
	}
	if s.config.IsConnected != nil && !s.config.IsConnected(s.current.resource) {
		return nil, ErrNotConnected
	}
	return s.current, nil
}
func (s *SingleSession[T]) Current() (T, error) {
	handle, err := s.CurrentHandle()
	if err != nil {
		var zero T
		return zero, err
	}
	return handle.resource, nil
}

func (s *SingleSession[T]) detachLocked() *SingleSessionHandle[T] {
	current := s.current
	s.current = nil
	if current != nil {
		current.lease.Invalidate(WrapFailure(net.ErrClosed, Failure{Resource: current.Ref(), Origin: OriginLocalCleanup, Scope: ScopeSharedResource, Layer: s.config.Layer}))
		current.cancel()
	}
	return current
}

func (s *SingleSession[T]) closeHandle(handle *SingleSessionHandle[T]) error {
	if handle == nil {
		return nil
	}
	return s.closeResource(handle.resource)
}

func (s *SingleSession[T]) closeResource(resource T) error {
	if s.config.Close == nil {
		return nil
	}
	return s.config.Close(resource)
}

func (s *SingleSession[T]) recordCloseError(err error) {
	s.cleanupErr = errors.Join(s.cleanupErr, err)
}

func (s *SingleSession[T]) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.cancel()
		current := s.detachLocked()
		s.transitionLocked(SessionClosed, nil)
		s.mu.Unlock()

		s.operation <- struct{}{}
		<-s.operation
		s.observers.Wait()
		s.recordCloseError(s.closeHandle(current))
	})
	return s.cleanupErr
}
