// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"net"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

type interfaceEvents struct{ change, reset func() }

// NewScope borrows one monitor and link cache. Close removes this scope's
// registrations and joins their callbacks without stopping sibling scopes.
func (m *InterfaceManager) NewScope() *InterfaceManager {
	if m.source != nil {
		m = m.source
	}
	return &InterfaceManager{source: m, stop: make(chan struct{}), done: make(chan struct{})}
}

func (m *InterfaceManager) registerScoped(name string, exact bool, initial func(netlink.Link) error, added, removed func(netlink.Link), synchronous bool) (*atomic.Bool, error) {
	m.mu.Lock()
	if m.isStopped() {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	m.registering.Add(1)
	m.mu.Unlock()
	defer m.registering.Done()
	registration, err := m.source.register(name, exact, initial, added, removed, synchronous)
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

func (m *InterfaceManager) closeScope() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		close(m.stop)
		registrations := m.registrations
		m.registrations = nil
		m.mu.Unlock()
		m.source.mu.Lock()
		delete(m.source.scopes, m)
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
	if m.source != nil {
		m.source.waitCallbacks()
		return
	}
	done := make(chan error, 1)
	if !m.enqueueDelivery([]func() error{func() error { return nil }}, done) {
		<-m.deliveryDone
		return
	}
	<-done
}

func (m *InterfaceManager) setScopeEvent(callback func(), reset bool) {
	source := m.source
	source.mu.Lock()
	defer source.mu.Unlock()
	if m.isStopped() || source.isStopped() {
		return
	}
	if source.scopes == nil {
		source.scopes = make(map[*InterfaceManager]interfaceEvents)
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
	direct := m.onChange
	if reset {
		direct = m.onReset
	}
	if direct != nil {
		callbacks = append(callbacks, voidCallback(direct))
	}
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
