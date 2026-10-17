// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func receiveLinkChange(t *testing.T, watch linkWatch, closed bool) {
	t.Helper()
	select {
	case _, ok := <-watch.updates:
		if ok == closed {
			t.Fatalf("link notification open = %v, want %v", ok, !closed)
		}
	case <-time.After(time.Second):
		t.Fatal("missing link notification")
	}
}

func TestInterfaceChangesIncludeAttributesAndCoalesce(t *testing.T) {
	source := scopeTestSource(t)
	scope := source.NewScope()
	t.Cleanup(func() { _ = scope.Close() })
	watch, err := scope.watchChanges()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.cancel)
	var added atomic.Int32
	if err := scope.RegisterSync("wan0", nil, func(netlink.Link) { added.Add(1) }, nil); err != nil {
		t.Fatal(err)
	}
	update := func(state netlink.LinkOperState) {
		source.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
			Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "wan0", OperState: state}}})
	}
	update(netlink.OperDown)
	receiveLinkChange(t, watch, false)
	for range 100 {
		update(netlink.OperUp)
	}
	receiveLinkChange(t, watch, false)
	select {
	case <-watch.updates:
		t.Fatal("attribute burst was not coalesced")
	default:
	}
	if added.Load() != 1 {
		t.Fatal("attribute updates re-entered lifecycle callbacks")
	}
	source.replaceLinks(nil)
	receiveLinkChange(t, watch, false)
}

func TestInterfaceChangesPrecedeSlowLifecycleCallback(t *testing.T) {
	source := scopeTestSource(t)
	watch, err := testInterfaceScope(t, source).watchChanges()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.cancel)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	if err := testInterfaceScope(t, source).RegisterSync("wan0", nil, func(netlink.Link) { close(entered); <-release }, nil); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(finished)
		source.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
			Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "wan0"}}})
	}()
	<-entered
	receiveLinkChange(t, watch, false)
	// The source must keep receiving while the first lifecycle callback blocks.
	source.queueLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "wan0", OperState: netlink.OperUp}}})
	receiveLinkChange(t, watch, false)
	unblock()
	<-finished
}

func TestInterfaceChangesCancelScopeAndSource(t *testing.T) {
	source, err := newInterfaceManager(func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		go func() { <-done; close(ch) }()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	first, second := source.NewScope(), source.NewScope()
	t.Cleanup(func() { first.Close(); second.Close() })
	a, err := first.watchChanges()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.watchChanges()
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	receiveLinkChange(t, a, true)
	a.cancel()
	if _, err := first.watchChanges(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed scope accepted watcher: %v", err)
	}
	source.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "wan0"}}})
	receiveLinkChange(t, b, false)
	source.Close()
	receiveLinkChange(t, b, true)
	b.cancel()
	if _, err := second.watchChanges(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed source accepted watcher: %v", err)
	}
}

func TestHostNetworkMonitorUsesSharedLinkChanges(t *testing.T) {
	source := scopeTestSource(t)
	scope := source.NewScope()
	t.Cleanup(func() { _ = scope.Close() })
	watch, err := scope.watchChanges()
	if err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	m := newHostNetworkMonitor(func() (HostNetworkSnapshot, error) {
		snapshot := HostNetworkSnapshot{Interfaces: []DefaultRouteInterface{{Index: 2, Name: "wan0", IPv4Default: true}}}
		if ready.Load() {
			snapshot.Interfaces[0].IPv4Source = "192.0.2.2"
		}
		return snapshot, nil
	}, watch, nil, nil, nil, nil, nil, time.Millisecond, time.Hour)
	t.Cleanup(func() { _ = m.Close() })
	changed := make(chan struct{}, 1)
	m.Register(func(_, next HostNetworkSnapshot) {
		if next.Ready() {
			changed <- struct{}{}
		}
	})
	deadline := time.Now().Add(time.Second)
	for m.Snapshot().Revision() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.Snapshot().Revision() == 0 {
		t.Fatal("initial snapshot was not published")
	}
	ready.Store(true)
	source.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "wan0", OperState: netlink.OperUp}}})
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("shared link event did not refresh host readiness")
	}
	m.Close()
	receiveLinkChange(t, watch, true)
	if source.isStopped() || scope.isStopped() {
		t.Fatal("host monitor closed its borrowed event source")
	}
}
