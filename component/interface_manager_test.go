/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"errors"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestInterfaceManagerCloseWaitsForCallback(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	m := &InterfaceManager{
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		upLinks: make(map[string]bool),
		callbacks: []callbackSet{{
			pattern: "test0",
			newCallback: func(netlink.Link) {
				close(started)
				<-release
			},
		}},
	}
	updates := make(chan netlink.LinkUpdate)
	go m.monitor(updates)
	updates <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "test0"}},
	}
	<-started
	producerDone := make(chan struct{})
	go func() {
		updates <- netlink.LinkUpdate{
			Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
			Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "test0"}},
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
	case <-m.stop:
	default:
		t.Fatal("monitor did not stop its netlink subscription")
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

func TestInterfaceManagerRejectsInvalidPattern(t *testing.T) {
	m, err := newInterfaceManager(func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		go func() {
			<-done
			close(ch)
		}()
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

func TestInterfaceManagerStopsWhenUpdateChannelCloses(t *testing.T) {
	m := &InterfaceManager{
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		upLinks: make(map[string]bool),
	}
	updates := make(chan netlink.LinkUpdate)
	go m.monitor(updates)
	close(updates)

	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop when its update channel closed")
	}
	select {
	case <-m.stop:
	default:
		t.Fatal("monitor did not stop its netlink subscription")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}
