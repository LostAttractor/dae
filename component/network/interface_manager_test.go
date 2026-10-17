/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package network

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestMatchingLinksFollowsLifecycleAndRecovery(t *testing.T) {
	m := testInterfaceSource(t, &InterfaceManager{links: make(map[int]netlink.Link)})
	scope := testInterfaceScope(t, m)
	assertNames := func(want ...string) {
		t.Helper()
		var got []string
		for _, link := range scope.MatchingLinks([]string{"eth*", "*0"}) {
			got = append(got, link.Attrs().Name)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("matching links = %v, want %v", got, want)
		}
	}
	update := func(typ uint16, index int, name string) {
		m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: typ}, Link: &netlink.Dummy{Index: index, Name: name}})
	}
	update(unix.RTM_NEWLINK, 2, "eth0")
	update(unix.RTM_NEWLINK, 3, "eth1")
	update(unix.RTM_NEWLINK, 4, "other")
	assertNames("eth0", "eth1") // Overlapping patterns cannot duplicate a link.
	update(unix.RTM_NEWLINK, 2, "wan1")
	assertNames("eth1")
	update(unix.RTM_DELLINK, 3, "eth1")
	assertNames()
	m.replaceLinks([]netlink.Link{&netlink.Dummy{Index: 5, Name: "lan0"}})
	assertNames("lan0")
}

func TestInterfaceManagerCloseWaitsForCallback(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	m := testInterfaceSource(t, &InterfaceManager{
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		links: make(map[int]netlink.Link),
		callbacks: []callbackSet{{
			pattern: "test0",
			newCallback: func(netlink.Link) {
				close(started)
				<-release
			},
		}},
	})
	updates := make(chan netlink.LinkUpdate)
	go m.monitor(updates, nil, nil)
	updates <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "test0"}},
	}
	<-started
	producerDone := make(chan struct{})
	go func() {
		updates <- netlink.LinkUpdate{
			Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
			Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "test0"}},
		}
		<-m.stop
		close(updates)
		close(producerDone)
	}()

	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before callback completion: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("Close returned before the subscription producer stopped")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInterfaceManagerDispatchesLinkLifecycle(t *testing.T) {
	var events []string
	m := testInterfaceSource(t, &InterfaceManager{
		links: make(map[int]netlink.Link),
		callbacks: []callbackSet{{
			pattern:     "test0",
			newCallback: func(netlink.Link) { events = append(events, "new") },
			delCallback: func(netlink.Link) { events = append(events, "del") },
		}},
	})
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "test0"}}
	m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: link})
	m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: link})
	m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_DELLINK}, Link: link})
	if len(events) != 2 || events[0] != "new" || events[1] != "del" {
		t.Fatalf("events = %v, want [new del]", events)
	}
}

func TestInterfaceManagerDispatchesRename(t *testing.T) {
	var events []string
	m := testInterfaceSource(t, &InterfaceManager{
		links: make(map[int]netlink.Link),
		callbacks: []callbackSet{
			{pattern: "old0", delCallback: func(netlink.Link) { events = append(events, "old-del") }},
			{pattern: "new0", newCallback: func(netlink.Link) { events = append(events, "new-add") }},
		},
	})
	testInterfaceScope(t, m).SetChangeCallback(func() { events = append(events, "reconcile") })
	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "old0"}},
	})
	if got := m.NameByIndex(2); got != "old0" {
		t.Fatalf("interface name = %q, want old0", got)
	}
	events = nil
	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "new0"}},
	})
	if len(events) != 3 || events[0] != "old-del" || events[1] != "new-add" || events[2] != "reconcile" {
		t.Fatalf("rename events = %v, want [old-del new-add reconcile]", events)
	}
	if got := m.NameByIndex(2); got != "new0" {
		t.Fatalf("renamed interface = %q, want new0", got)
	}
	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_DELLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "new0"}},
	})
	if got := m.NameByIndex(2); got != "" {
		t.Fatalf("deleted interface name = %q, want empty", got)
	}
}

func TestInterfaceManagerRejectsInvalidPattern(t *testing.T) {
	m, err := newInterfaceManager(func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		go func() { <-done; close(ch) }()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := testInterfaceScope(t, m).RegisterWithPatternSync("[", nil, nil, nil); err == nil {
		t.Fatal("invalid interface pattern was accepted")
	}
}

func TestInterfaceManagerRejectsRegistrationAfterInitialListFailure(t *testing.T) {
	listErr := errors.New("temporary list failure")
	m := testInterfaceSource(t, &InterfaceManager{listLinks: func() ([]netlink.Link, error) { return nil, listErr }})
	scope := testInterfaceScope(t, m)
	called := false
	if err := scope.RegisterWithPatternSync("test0", nil, func(netlink.Link) { called = true }, nil); !errors.Is(err, listErr) {
		t.Fatalf("registration error = %v, want %v", err, listErr)
	}
	m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: &netlink.Dummy{Index: 2, Name: "test0"}})
	if called || len(m.callbacks) != 0 {
		t.Fatal("failed initial dump retained a registration")
	}
	m.listLinks = func() ([]netlink.Link, error) { return nil, nil }
	if err := scope.RegisterWithPatternSync("test0", nil, func(netlink.Link) { called = true }, nil); err != nil {
		t.Fatal(err)
	}
	m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: &netlink.Dummy{Index: 3, Name: "test0"}})
	if !called {
		t.Fatal("explicit retry did not register")
	}
}

func TestInterfaceManagerReportsSubscriptionFailure(t *testing.T) {
	subscribeErr := errors.New("subscription failed")
	var subscriptionDone <-chan struct{}
	m, err := newInterfaceManager(func(_ chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		subscriptionDone = done
		return subscribeErr
	})
	if m != nil {
		t.Fatal("manager returned after subscription failure")
	}
	if !errors.Is(err, subscribeErr) {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case <-subscriptionDone:
	default:
		t.Fatal("failed subscription was not stopped")
	}
}

func TestInterfaceManagerRetriesLinkListAfterResubscribe(t *testing.T) {
	logger := log.StandardLogger()
	hooks, level := logger.ReplaceHooks(make(log.LevelHooks)), logger.GetLevel()
	hook := logtest.NewGlobal()
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.ReplaceHooks(hooks)
		logger.SetLevel(level)
	})
	oldLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "old0"}}
	newLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "new0"}}
	events := make(chan string, 4)
	m := testInterfaceSource(t, &InterfaceManager{
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		links: map[int]netlink.Link{1: oldLink},
		callbacks: []callbackSet{{
			pattern:     "*",
			newCallback: func(link netlink.Link) { events <- "new:" + link.Attrs().Name },
			delCallback: func(link netlink.Link) { events <- "del:" + link.Attrs().Name },
		}},
	})
	scope := testInterfaceScope(t, m)
	scope.SetResetCallback(func() { events <- "reset" })
	scope.SetChangeCallback(func() { events <- "change" })
	subscribed := make(chan chan<- netlink.LinkUpdate, 1)
	subscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		subscribed <- ch
		go func() {
			<-done
			close(ch)
		}()
		return nil
	}
	watch, err := testInterfaceScope(t, m).watchChanges()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.cancel)
	updates := make(chan netlink.LinkUpdate)
	var listCalls atomic.Int32
	go m.monitor(updates, subscribe, func() ([]netlink.Link, error) {
		if listCalls.Add(1) == 1 {
			return nil, errors.New("temporary list failure")
		}
		return []netlink.Link{newLink}, nil
	})
	close(updates)
	receiveLinkChange(t, watch, false)

	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not resubscribe")
	}
	for _, want := range []string{"reset", "del:old0", "new:new0", "change"} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("event = %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing %q event", want)
		}
	}
	receiveLinkChange(t, watch, false)
	if got := listCalls.Load(); got != 2 {
		t.Fatalf("LinkList calls = %d, want 2", got)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	entries := hook.AllEntries()
	if len(entries) != 2 || entries[0].Level != log.WarnLevel || entries[1].Level != log.InfoLevel {
		t.Fatalf("monitor should report one interruption and one recovery: %+v", entries)
	}
}

func TestInterfaceManagerCallbackCanReadCachedLinks(t *testing.T) {
	m := testInterfaceSource(t, &InterfaceManager{listLinks: func() ([]netlink.Link, error) { return nil, nil }})
	scope := testInterfaceScope(t, m)
	var name string
	if err := scope.RegisterSync("test0", nil, func(link netlink.Link) {
		name = scope.NameByIndex(link.Attrs().Index)
	}, nil); err != nil {
		t.Fatal(err)
	}
	m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: &netlink.Dummy{Index: 1, Name: "test0"}})
	if name != "test0" {
		t.Fatalf("callback saw name %q", name)
	}
}

func TestInterfaceManagerSyncInitErrorDisablesRegistration(t *testing.T) {
	initErr := errors.New("initial callback failed")
	m := testInterfaceSource(t, &InterfaceManager{
		links: make(map[int]netlink.Link),
		listLinks: func() ([]netlink.Link, error) {
			return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "test0"}}}, nil
		},
	})
	called := false
	err := testInterfaceScope(t, m).RegisterSync("test0", func(netlink.Link) error { return initErr }, func(netlink.Link) { called = true }, nil)
	if !errors.Is(err, initErr) {
		t.Fatalf("RegisterSync error = %v, want %v", err, initErr)
	}
	if len(m.callbacks) != 0 {
		t.Fatal("failed synchronous registration remained active")
	}
	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "test0"}},
	})
	if called {
		t.Fatal("failed registration received a dynamic callback")
	}
}

func TestInterfaceManagerCancelableRegistration(t *testing.T) {
	m := testInterfaceSource(t, &InterfaceManager{
		links:     make(map[int]netlink.Link),
		listLinks: func() ([]netlink.Link, error) { return nil, nil },
	})
	called := false
	cancel, err := testInterfaceScope(t, m).RegisterSyncCancelable("test0", nil, func(netlink.Link) { called = true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.callbacks) != 1 {
		t.Fatalf("callbacks = %d, want 1", len(m.callbacks))
	}
	cancel()
	cancel()
	if len(m.callbacks) != 0 {
		t.Fatalf("callbacks after cancel = %d, want 0", len(m.callbacks))
	}
	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "test0"}},
	})
	if called {
		t.Fatal("cancelled registration received an update")
	}
}

func TestInterfaceManagerExactRegistrationTreatsNameLiterally(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "test[0]"}}
	m := testInterfaceSource(t, &InterfaceManager{
		links:     make(map[int]netlink.Link),
		listLinks: func() ([]netlink.Link, error) { return []netlink.Link{link}, nil },
	})
	called := false
	if err := testInterfaceScope(t, m).RegisterSync("test[0]", func(netlink.Link) error {
		called = true
		return nil
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("literal interface name did not match")
	}
}

func TestInterfaceManagerCancelJoinsDispatchedCallbackDuringShutdown(t *testing.T) {
	for _, stopping := range []bool{false, true} {
		t.Run(fmt.Sprintf("stopping=%v", stopping), func(t *testing.T) {
			m := testInterfaceSource(t, &InterfaceManager{links: make(map[int]netlink.Link), listLinks: func() ([]netlink.Link, error) { return nil, nil }, deliveryDone: make(chan struct{})})
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			var writes atomic.Int32
			cancel, err := testInterfaceScope(t, m).RegisterSyncCancelable("test0", nil, func(netlink.Link) { close(started); <-release; writes.Add(1) }, nil)
			if err != nil {
				t.Fatal(err)
			}
			delivered := make(chan struct{})
			go func() {
				m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "test0"}}})
				close(delivered)
			}()
			<-started
			if stopping {
				m.deliveryMu.Lock()
				m.deliveryStopping = true
				m.deliveryMu.Unlock()
			}
			cancelled := make(chan struct{})
			go func() { cancel(); close(cancelled) }()
			select {
			case <-cancelled:
				t.Fatal("cancel returned while callback could still write old routing state")
			case <-time.After(20 * time.Millisecond):
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("cancel did not join callback")
			}
			<-delivered
			if writes.Load() != 1 {
				t.Fatal("callback was not drained")
			}
		})
	}
}
