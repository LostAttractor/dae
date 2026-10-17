// SPDX-License-Identifier: AGPL-3.0-only

package network

import "net"

// linkWatch invalidates a snapshot; it does not own kernel subscriptions or
// carry mutable link objects. A slow consumer coalesces updates into one wakeup.
type linkWatch struct {
	updates <-chan struct{}
	cancel  func()
}

func (m *InterfaceScope) watchChanges() (linkWatch, error) {
	source := m.source
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.isStopped() || m.isStopped() {
		return linkWatch{}, net.ErrClosed
	}
	updates := make(chan struct{}, 1)
	if source.changes == nil {
		source.changes = make(map[chan struct{}]*InterfaceScope)
	}
	source.changes[updates] = m
	return linkWatch{updates: updates, cancel: func() {
		source.mu.Lock()
		defer source.mu.Unlock()
		if _, ok := source.changes[updates]; ok {
			delete(source.changes, updates)
			close(updates)
		}
	}}, nil
}

// Called under the source lock, before lifecycle callback delivery. Attribute
// changes (including carrier/operstate) matter even when the name is unchanged.
func (m *InterfaceManager) notifyChangesLocked() {
	for updates := range m.changes {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
}

func (m *InterfaceManager) closeChangesLocked(owner *InterfaceScope) {
	for updates, scope := range m.changes {
		if owner == nil || scope == owner {
			delete(m.changes, updates)
			close(updates)
		}
	}
}
