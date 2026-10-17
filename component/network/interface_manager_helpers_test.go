// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vishvananda/netlink"
)

// Fixtures use the production dispatcher with hand-written link sources.
func testInterfaceSource(t *testing.T, source *InterfaceManager) *InterfaceManager {
	t.Helper()
	if source.stop == nil {
		source.stop = make(chan struct{})
	}
	if source.done == nil {
		source.done = make(chan struct{})
	}
	if source.links == nil {
		source.links = make(map[int]netlink.Link)
	}
	if source.listLinks == nil {
		source.listLinks = func() ([]netlink.Link, error) { return nil, nil }
	}
	for i := range source.callbacks {
		source.callbacks[i].active = new(atomic.Bool)
		source.callbacks[i].active.Store(true)
	}
	source.deliveryDone = make(chan struct{})
	source.deliveryCond = sync.NewCond(&source.deliveryMu)
	go source.dispatchCallbacks()
	t.Cleanup(func() {
		source.stopSubscription()
		source.stopCallbackDispatcher()
	})
	return source
}

func testInterfaceScope(t *testing.T, source *InterfaceManager) *InterfaceScope {
	t.Helper()
	scope := source.NewScope()
	t.Cleanup(func() { _ = scope.Close() })
	return scope
}

// Tests that assert lifecycle effects wait for the ordered dispatcher.
func (m *InterfaceManager) handleLinkUpdate(update netlink.LinkUpdate) {
	if done := m.queueLinkUpdate(update); done != nil {
		<-done
	}
}
