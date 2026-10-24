// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"path/filepath"
	"sync"

	"github.com/daeuniverse/dae/component/plugin"
)

// StatePool owns reload-independent plugin state. Its zero value is ready to use.
// StopAcquiring ends admission; Close runs after all plugin users have stopped.
type StatePool struct {
	mu        sync.Mutex
	states    map[string]*sharedState
	stopped   bool
	stop      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

type sharedState struct {
	value   io.Closer
	refs    int
	pending chan struct{}
}

var _ plugin.SharedStates = (*StatePool)(nil)

func (p *StatePool) Acquire(ctx context.Context, key string, build func() (io.Closer, error)) (io.Closer, func() error, error) {
	for {
		p.mu.Lock()
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, nil, err
		}
		if p.stopped {
			p.mu.Unlock()
			return nil, nil, net.ErrClosed
		}
		if entry := p.states[key]; entry != nil {
			if entry.pending != nil {
				ready, stop := entry.pending, p.stop
				p.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-stop:
					return nil, nil, net.ErrClosed
				case <-ready:
					continue
				}
			}
			entry.refs++
			p.mu.Unlock()
			return entry.value, p.lease(key, entry), nil
		}
		if p.states == nil {
			p.states = make(map[string]*sharedState)
			p.stop = make(chan struct{})
		}
		entry := &sharedState{pending: make(chan struct{})}
		p.states[key] = entry
		p.mu.Unlock()

		value, err := build()
		if err == nil && value == nil {
			err = errors.New("shared state builder returned nil")
		}
		p.mu.Lock()
		if err != nil {
			delete(p.states, key)
			close(entry.pending)
			p.mu.Unlock()
			return nil, nil, err
		}
		entry.value = value
		err = ctx.Err()
		if err == nil && p.stopped {
			err = net.ErrClosed
		}
		if err != nil {
			p.mu.Unlock()
			return nil, nil, errors.Join(err, p.closeState(key, entry))
		}
		entry.refs = 1
		close(entry.pending)
		entry.pending = nil
		p.mu.Unlock()
		return value, p.lease(key, entry), nil
	}
}

func (p *StatePool) lease(key string, entry *sharedState) func() error {
	return sync.OnceValue(func() error {
		p.mu.Lock()
		entry.refs--
		// Shutdown owns the final close after all users stop. A release must not
		// race it or retry a failed close while another lease still uses the state.
		if entry.refs != 0 || p.stopped {
			p.mu.Unlock()
			return nil
		}
		entry.pending = make(chan struct{})
		p.mu.Unlock()
		return p.closeState(key, entry)
	})
}

// closeState keeps registration until Close succeeds, including cancelled builds.
func (p *StatePool) closeState(key string, entry *sharedState) error {
	err := entry.value.Close()
	p.mu.Lock()
	if err == nil {
		delete(p.states, key)
	}
	close(entry.pending)
	entry.pending = nil
	p.mu.Unlock()
	return err
}

// StopAcquiring rejects new leases without closing state still used by plugins.
func (p *StatePool) StopAcquiring() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.stopped {
		p.stopped = true
		if p.stop != nil {
			close(p.stop)
		}
	}
}

// Close independently waits for each state's in-flight work, then retries its close.
// Callers must stop plugin users first, even if leases remain outstanding.
func (p *StatePool) Close() error {
	p.StopAcquiring()
	p.closeOnce.Do(func() {
		p.mu.Lock()
		remaining := maps.Clone(p.states)
		p.mu.Unlock()
		var closing sync.WaitGroup
		closeErrors := make(chan error, len(remaining))
		for key, entry := range remaining {
			closing.Go(func() {
				p.mu.Lock()
				if ready := entry.pending; ready != nil {
					p.mu.Unlock()
					<-ready
					p.mu.Lock()
				}
				if p.states[key] != entry {
					p.mu.Unlock()
					return
				}
				// Admission is stopped, so no new build or release can claim this entry.
				entry.pending = make(chan struct{})
				p.mu.Unlock()
				closeErrors <- p.closeState(key, entry)
			})
		}
		closing.Wait()
		close(closeErrors)
		for err := range closeErrors {
			p.closeErr = errors.Join(p.closeErr, err)
		}
	})
	return p.closeErr
}

type scopedStates struct {
	pool      plugin.SharedStates
	namespace string
}

func scopeStates(pool plugin.SharedStates, baseDir string, spec plugin.Spec) (plugin.SharedStates, error) {
	if pool == nil {
		return nil, nil
	}
	if baseDir != "" {
		var err error
		baseDir, err = filepath.Abs(baseDir)
		if err != nil {
			return nil, err
		}
	}
	// Length prefixes keep arbitrary separators in instance IDs and keys distinct.
	namespace := fmt.Sprintf("%d:%s%d:%s%d:%s", len(baseDir), baseDir, len(spec.Type), spec.Type, len(spec.ID), spec.ID)
	return scopedStates{pool: pool, namespace: namespace}, nil
}

func (s scopedStates) Acquire(ctx context.Context, key string, build func() (io.Closer, error)) (io.Closer, func() error, error) {
	return s.pool.Acquire(ctx, s.namespace+key, build)
}
