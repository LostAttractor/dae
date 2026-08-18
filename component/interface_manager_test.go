/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestInterfaceManagerCloseWaitsForCallback(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	m := &InterfaceManager{
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
	}
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
	m := &InterfaceManager{
		links: make(map[int]netlink.Link),
		callbacks: []callbackSet{{
			pattern:     "test0",
			newCallback: func(netlink.Link) { events = append(events, "new") },
			delCallback: func(netlink.Link) { events = append(events, "del") },
		}},
	}
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
	m := &InterfaceManager{
		links: make(map[int]netlink.Link),
		callbacks: []callbackSet{
			{pattern: "old0", delCallback: func(netlink.Link) { events = append(events, "old-del") }},
			{pattern: "new0", newCallback: func(netlink.Link) { events = append(events, "new-add") }},
		},
		onChange: func() { events = append(events, "reconcile") },
	}
	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "old0"}},
	})
	events = nil
	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "new0"}},
	})
	if len(events) != 3 || events[0] != "old-del" || events[1] != "new-add" || events[2] != "reconcile" {
		t.Fatalf("rename events = %v, want [old-del new-add reconcile]", events)
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
	if err := m.RegisterWithPattern("[", nil, nil, nil); err == nil {
		t.Fatal("invalid interface pattern was accepted")
	}
}

func TestInterfaceManagerRetainsRegistrationAfterInitialListFailure(t *testing.T) {
	listErr := errors.New("temporary list failure")
	called := make(chan int, 1)
	m := &InterfaceManager{
		links: make(map[int]netlink.Link),
		listLinks: func() ([]netlink.Link, error) {
			return nil, listErr
		},
	}
	err := m.RegisterWithPattern("test0", nil, func(link netlink.Link) {
		called <- link.Attrs().Index
	}, nil)
	if !errors.Is(err, listErr) {
		t.Fatalf("registration error = %v, want %v", err, listErr)
	}

	m.handleLinkUpdate(netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "test0"}},
	})
	select {
	case index := <-called:
		if index != 2 {
			t.Fatalf("callback ifindex = %d, want 2", index)
		}
	case <-time.After(time.Second):
		t.Fatal("registration was lost after initial LinkList failure")
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
	oldLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "old0"}}
	newLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "new0"}}
	events := make(chan string, 3)
	m := &InterfaceManager{
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		links: map[int]netlink.Link{1: oldLink},
		callbacks: []callbackSet{{
			pattern:     "*",
			newCallback: func(link netlink.Link) { events <- "new:" + link.Attrs().Name },
			delCallback: func(link netlink.Link) { events <- "del:" + link.Attrs().Name },
		}},
		onReset: func() { events <- "reset" },
	}
	subscribed := make(chan chan<- netlink.LinkUpdate, 1)
	subscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		subscribed <- ch
		go func() {
			<-done
			close(ch)
		}()
		return nil
	}
	updates := make(chan netlink.LinkUpdate)
	var listCalls atomic.Int32
	go m.monitor(updates, subscribe, func() ([]netlink.Link, error) {
		if listCalls.Add(1) == 1 {
			return nil, errors.New("temporary list failure")
		}
		return []netlink.Link{newLink}, nil
	})
	close(updates)

	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not resubscribe")
	}
	for _, want := range []string{"reset", "del:old0", "new:new0"} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("event = %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing %q event", want)
		}
	}
	if got := listCalls.Load(); got != 2 {
		t.Fatalf("LinkList calls = %d, want 2", got)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}
