/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestInterfaceManagerCloseWaitsForCallback(t *testing.T) {
	closed, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	m := &InterfaceManager{
		closed:  closed,
		close:   cancel,
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
	updates := make(chan netlink.LinkUpdate, 1)
	subscriptionDone := make(chan struct{})
	go m.monitor(updates, subscriptionDone)
	updates <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "test0"}},
	}
	<-started

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
	case <-subscriptionDone:
	default:
		t.Fatal("monitor did not stop its netlink subscription")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}
