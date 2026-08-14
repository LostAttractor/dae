/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"fmt"
	"path"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type callbackSet struct {
	pattern     string
	newCallback func(netlink.Link)
	delCallback func(netlink.Link)
}

type InterfaceManager struct {
	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
	mu        sync.Mutex
	callbacks []callbackSet
	upLinks   map[string]bool
}

type linkSubscribeFunc func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error

func NewInterfaceManager() (*InterfaceManager, error) {
	return newInterfaceManager(netlink.LinkSubscribeWithOptions)
}

func newInterfaceManager(subscribe linkSubscribeFunc) (*InterfaceManager, error) {
	mgr := &InterfaceManager{
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		upLinks: make(map[string]bool),
	}

	ch := make(chan netlink.LinkUpdate)
	if err := subscribe(ch, mgr.stop, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			select {
			case <-mgr.stop:
				return
			default:
			}
			log.Warn("LinkSubscribe: ", err)
		},
		ListExisting: true,
	}); err != nil {
		mgr.stopSubscription()
		return nil, fmt.Errorf("subscribe to link updates: %w", err)
	}

	go mgr.monitor(ch)
	return mgr, nil
}

func (m *InterfaceManager) stopSubscription() {
	m.closeOnce.Do(func() { close(m.stop) })
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate) {
	defer close(m.done)
	for {
		select {
		case <-m.stop:
			// LinkSubscribeWithOptions can block while sending an update. Drain
			// until it closes ch so Close also joins the subscription goroutine.
			for range ch {
			}
			return
		case update, ok := <-ch:
			if !ok {
				m.stopSubscription()
				return
			}
			ifName := update.Link.Attrs().Name

			m.mu.Lock()
			isNew := false
			switch update.Header.Type {
			case unix.RTM_NEWLINK:
				if m.upLinks[ifName] {
					m.mu.Unlock()
					continue
				}
				m.upLinks[ifName] = true
				isNew = true
			case unix.RTM_DELLINK:
				delete(m.upLinks, ifName)
			default:
				m.mu.Unlock()
				continue
			}
			for _, callbacks := range m.callbacks {
				matched, err := path.Match(callbacks.pattern, ifName)
				if err != nil || !matched {
					continue
				}
				callback := callbacks.delCallback
				if isNew {
					callback = callbacks.newCallback
				}
				if callback != nil {
					callback(update.Link)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *InterfaceManager) RegisterWithPattern(pattern string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) error {
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid interface pattern %q: %w", pattern, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list interfaces for pattern %q: %w", pattern, err)
	}
	for _, link := range links {
		ifname := link.Attrs().Name
		if matched, _ := path.Match(pattern, ifname); matched {
			m.upLinks[ifname] = true

			if initCallback != nil {
				initCallback(link)
			}
		}
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     pattern,
		newCallback: newCallback,
		delCallback: delCallback,
	})
	return nil
}

func (m *InterfaceManager) Register(ifname string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := netlink.LinkByName(ifname)
	if err == nil {
		m.upLinks[ifname] = true

		if initCallback != nil {
			initCallback(link)
		}
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     ifname,
		newCallback: newCallback,
		delCallback: delCallback,
	})
}

// Close stops the monitor and waits for any callback already in progress.
func (m *InterfaceManager) Close() error {
	m.stopSubscription()
	<-m.done
	return nil
}
