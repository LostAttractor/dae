// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

type interfaceEvents struct{ change, reset func() }

// InterfaceScope owns one consumer's subscriptions, never the kernel source.
// Closing it joins its callbacks without stopping sibling consumers.
type InterfaceScope struct {
	source        *InterfaceManager
	mu            sync.Mutex
	registrations []*atomic.Bool
	registering   sync.WaitGroup
	closeOnce     sync.Once
	stop, done    chan struct{}
}

// NewScope borrows this source's monitor and cache.
func (m *InterfaceManager) NewScope() *InterfaceScope {
	return &InterfaceScope{source: m, stop: make(chan struct{}), done: make(chan struct{})}
}

// RegisterWithPatternSync waits for the initial callbacks. Registration and
// cancellation must not be called from an interface callback.
func (m *InterfaceScope) RegisterWithPatternSync(pattern string, initial func(netlink.Link) error, added, removed func(netlink.Link)) error {
	_, err := m.register(pattern, false, initial, added, removed)
	return err
}

// RegisterSync treats the interface name literally rather than as a pattern.
func (m *InterfaceScope) RegisterSync(name string, initial func(netlink.Link) error, added, removed func(netlink.Link)) error {
	_, err := m.register(name, true, initial, added, removed)
	return err
}

// RegisterSyncCancelable returns an idempotent cancellation that also joins
// callbacks already queued for this registration.
func (m *InterfaceScope) RegisterSyncCancelable(name string, initial func(netlink.Link) error, added, removed func(netlink.Link)) (func(), error) {
	registration, err := m.register(name, true, initial, added, removed)
	if err != nil {
		return nil, err
	}
	return sync.OnceFunc(func() {
		m.source.disableRegistration(registration)
		m.source.waitCallbacks()
	}), nil
}

func (m *InterfaceScope) NameByIndex(index int) string {
	if m == nil {
		return ""
	}
	return m.source.NameByIndex(index)
}

func (m *InterfaceScope) MatchingLinks(patterns []string) []netlink.Link {
	return m.source.MatchingLinks(patterns)
}

func (m *InterfaceScope) SetChangeCallback(callback func()) { m.setEvent(callback, false) }
func (m *InterfaceScope) SetResetCallback(callback func())  { m.setEvent(callback, true) }

func (m *InterfaceScope) isStopped() bool {
	select {
	case <-m.stop:
		return true
	default:
		return false
	}
}

func (m *InterfaceScope) register(name string, exact bool, initial func(netlink.Link) error, added, removed func(netlink.Link)) (*atomic.Bool, error) {
	m.mu.Lock()
	if m.isStopped() {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	m.registering.Add(1)
	m.mu.Unlock()
	defer m.registering.Done()
	registration, err := m.source.register(name, exact, initial, added, removed)
	if registration == nil {
		return nil, err
	}
	m.mu.Lock()
	stopped := m.isStopped()
	if !stopped {
		m.registrations = append(m.registrations, registration)
	}
	m.mu.Unlock()
	if stopped {
		m.source.disableRegistration(registration)
		return nil, net.ErrClosed
	}
	return registration, err
}

func (m *InterfaceScope) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		close(m.stop)
		registrations := m.registrations
		m.registrations = nil
		m.mu.Unlock()
		m.source.mu.Lock()
		delete(m.source.scopes, m)
		m.source.closeChangesLocked(m)
		m.source.mu.Unlock()
		for _, registration := range registrations {
			m.source.disableRegistration(registration)
		}
		// A registration already doing its initial callback cancels itself if
		// Close won the race. Join it before the final callback barrier.
		m.registering.Wait()
		m.source.waitCallbacks()
		close(m.done)
	})
	<-m.done
	return nil
}

func (m *InterfaceManager) waitCallbacks() {
	done := make(chan error, 1)
	if !m.enqueueDelivery([]func() error{func() error { return nil }}, done) {
		<-m.deliveryDone
		return
	}
	<-done
}

func (m *InterfaceScope) setEvent(callback func(), reset bool) {
	source := m.source
	source.mu.Lock()
	defer source.mu.Unlock()
	if m.isStopped() || source.isStopped() {
		return
	}
	if source.scopes == nil {
		source.scopes = make(map[*InterfaceScope]interfaceEvents)
	}
	events := source.scopes[m]
	if reset {
		events.reset = callback
	} else {
		events.change = callback
	}
	source.scopes[m] = events
}

// Called under the source mutex. Snapshot callbacks with their scope's gate so
// a queued event cannot enter a generation after that scope has been closed.
func (m *InterfaceManager) eventCallbacksLocked(reset bool) []func() error {
	var callbacks []func() error
	for scope, events := range m.scopes {
		callback := events.change
		if reset {
			callback = events.reset
		}
		if callback != nil {
			callbacks = append(callbacks, func() error {
				if !scope.isStopped() {
					callback()
				}
				return nil
			})
		}
	}
	return callbacks
}
