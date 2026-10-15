package netproxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var identity atomic.Uint64
var ErrDependencyInvalid = errors.New("outbound dependency is no longer available")

func NewResourceRef() ResourceRef {
	id := identity.Add(1)
	return ResourceRef{OwnerID: id, ResourceID: id, Generation: 1}
}

// Lease records the actual resources used at establishment time. Invalidation
// synchronously closes allocation gates throughout that dependency subtree;
// blocking protocol cleanup is performed separately by each resource owner.
type Lease struct {
	ref      ResourceRef
	stream   *StreamRef
	mu       sync.Mutex
	aborted  bool
	cause    error // nil until the first invalidation
	children map[*Lease]struct{}
	parents  []*Lease
	done     chan struct{}
}

func NewLease(ref ResourceRef, parents ...*Lease) *Lease { return newLease(ref, nil, parents) }
func newLease(ref ResourceRef, stream *StreamRef, parents []*Lease) *Lease {
	l := &Lease{ref: ref, stream: stream, parents: append([]*Lease(nil), parents...), children: make(map[*Lease]struct{}), done: make(chan struct{})}
	for _, parent := range l.parents {
		if parent == nil {
			continue
		}
		parent.mu.Lock()
		l.mu.Lock()
		if l.cause != nil {
			l.mu.Unlock()
			parent.mu.Unlock()
			break
		}
		if parent.cause != nil {
			cause, aborted := parent.cause, parent.aborted
			l.mu.Unlock()
			parent.mu.Unlock()
			l.invalidate(cause, aborted)
			break
		}
		parent.children[l] = struct{}{}
		l.mu.Unlock()
		parent.mu.Unlock()
	}
	return l
}
func (l *Lease) Resource() ResourceRef {
	if l == nil {
		return ResourceRef{}
	}
	return l.ref
}
func (l *Lease) Stream() *StreamRef {
	if l == nil || l.stream == nil {
		return nil
	}
	v := *l.stream
	return &v
}
func (l *Lease) Valid() bool {
	cause, _ := l.termination()
	return cause == nil
}
func (l *Lease) Done() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.done
}
func (l *Lease) Cause() error {
	cause, _ := l.termination()
	return cause
}

// AbortCause reports the owner's instruction to terminate dependent work.
// Ordinary invalidation and local cleanup do not issue that instruction.
func (l *Lease) AbortCause() error {
	if cause, aborted := l.termination(); aborted {
		return cause
	}
	return nil
}

// Consult parent gates until propagation reaches this lease. All readers use
// the same cause and action, and a finished child keeps its original result.
func (l *Lease) termination() (cause error, aborted bool) {
	if l == nil {
		return nil, false
	}
	l.mu.Lock()
	cause, aborted = l.cause, l.aborted
	l.mu.Unlock()
	if cause != nil {
		return cause, aborted
	}
	for _, parent := range l.parents {
		if cause, aborted = parent.termination(); cause != nil {
			return cause, aborted
		}
	}
	return nil, false
}

func (l *Lease) NewStream() *Lease {
	ref := l.Resource()
	return newLease(ref, &StreamRef{Parent: ref, ID: identity.Add(1)}, []*Lease{l})
}
func (l *Lease) Invalidate(cause error) bool {
	return l.invalidate(cause, false)
}

// Abort invalidates this dependency subtree and instructs its active consumers
// to terminate immediately. The first invalidation fixes both cause and action.
func (l *Lease) Abort(cause error) bool {
	return l.invalidate(cause, true)
}

func (l *Lease) invalidate(cause error, aborted bool) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	if l.cause != nil {
		l.mu.Unlock()
		return false
	}
	if cause == nil {
		cause = ErrDependencyInvalid
	}
	l.cause, l.aborted = cause, aborted
	children := make([]*Lease, 0, len(l.children))
	for c := range l.children {
		children = append(children, c)
	}
	clear(l.children)
	close(l.done)
	l.mu.Unlock()
	for _, child := range children {
		child.invalidate(cause, aborted)
	}
	for _, parent := range l.parents {
		if parent != nil {
			parent.mu.Lock()
			delete(parent.children, l)
			parent.mu.Unlock()
		}
	}
	return true
}

type DependencyProvider interface{ DependencyLease() *Lease }

func DependencyOf(value any) *Lease {
	if p, ok := value.(DependencyProvider); ok {
		return p.DependencyLease()
	}
	return nil
}

type dependencyCollector struct {
	mu     sync.Mutex
	leases []*Lease
}
type dependencyContextKey struct{}

func collectDependencies(ctx context.Context) (context.Context, *dependencyCollector) {
	c := new(dependencyCollector)
	return context.WithValue(ctx, dependencyContextKey{}, c), c
}
func (c *dependencyCollector) snapshot() []*Lease {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*Lease(nil), c.leases...)
}

// CaptureDependency must be called immediately after obtaining a parent tunnel.
// A context without a collector is valid (e.g. a stateless final dial).
func CaptureDependency(ctx context.Context, conn any) {
	lease := DependencyOf(conn)
	if lease == nil {
		return
	}
	c, _ := ctx.Value(dependencyContextKey{}).(*dependencyCollector)
	if c == nil {
		return
	}
	c.mu.Lock()
	c.leases = append(c.leases, lease)
	c.mu.Unlock()
}
