/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"fmt"
	"path"
	"sync"
	"time"

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
	onChange  func()
	onReset   func()
	links     map[int]netlink.Link
	listLinks linkListFunc
}

type linkSubscribeFunc func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error
type linkListFunc func() ([]netlink.Link, error)

const interfaceSubscribeRetryInterval = time.Second

func NewInterfaceManager() (*InterfaceManager, error) {
	return newInterfaceManager(netlink.LinkSubscribeWithOptions)
}

func newInterfaceManager(subscribe linkSubscribeFunc) (*InterfaceManager, error) {
	mgr := &InterfaceManager{
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		links:     make(map[int]netlink.Link),
		listLinks: netlink.LinkList,
	}

	ch, err := mgr.subscribe(subscribe)
	if err != nil {
		mgr.stopSubscription()
		return nil, fmt.Errorf("subscribe to link updates: %w", err)
	}

	go mgr.monitor(ch, subscribe, netlink.LinkList)
	return mgr, nil
}

func (m *InterfaceManager) subscribe(subscribe linkSubscribeFunc) (chan netlink.LinkUpdate, error) {
	ch := make(chan netlink.LinkUpdate)
	err := subscribe(ch, m.stop, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			select {
			case <-m.stop:
				return
			default:
			}
			log.Warn("LinkSubscribe: ", err)
		},
		ListExisting: true,
	})
	return ch, err
}

func (m *InterfaceManager) stopSubscription() {
	m.closeOnce.Do(func() { close(m.stop) })
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate, subscribe linkSubscribeFunc, listLinks linkListFunc) {
	defer close(m.done)
	drain := func() {
		if ch != nil {
			for range ch {
			}
		}
	}
	rebuild := func() bool {
		timer := time.NewTimer(interfaceSubscribeRetryInterval)
		defer timer.Stop()
		for {
			select {
			case <-m.stop:
				drain()
				return false
			case update, ok := <-ch:
				if !ok {
					ch = nil
					continue
				}
				m.handleLinkUpdate(update)
			case <-timer.C:
				if ch == nil {
					next, err := m.subscribe(subscribe)
					if err != nil {
						log.Warn("LinkSubscribe: ", err)
						timer.Reset(interfaceSubscribeRetryInterval)
						continue
					}
					ch = next
				}
				links, err := listLinks()
				if err != nil {
					log.Warn("LinkList after resubscribe: ", err)
					timer.Reset(interfaceSubscribeRetryInterval)
					continue
				}
				m.replaceLinks(links)
				return true
			}
		}
	}
	for {
		select {
		case <-m.stop:
			// LinkSubscribeWithOptions can block while sending an update. Drain
			// until it closes ch so Close also joins the subscription goroutine.
			drain()
			return
		case update, ok := <-ch:
			if !ok {
				ch = nil
				if !rebuild() {
					return
				}
				continue
			}
			m.handleLinkUpdate(update)
		}
	}
}

func (m *InterfaceManager) replaceLinks(links []netlink.Link) {
	m.mu.Lock()
	previous := make([]netlink.Link, 0, len(m.links))
	for _, link := range m.links {
		previous = append(previous, link)
	}
	onReset := m.onReset
	m.mu.Unlock()
	if onReset != nil {
		onReset()
	}
	for _, link := range previous {
		m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_DELLINK}, Link: link})
	}
	for _, link := range links {
		m.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: link})
	}
}

func (m *InterfaceManager) handleLinkUpdate(update netlink.LinkUpdate) {
	if update.Link == nil {
		return
	}
	attrs := update.Link.Attrs()
	m.mu.Lock()
	callbacks := append([]callbackSet(nil), m.callbacks...)
	onChange := m.onChange
	var previous netlink.Link
	switch update.Header.Type {
	case unix.RTM_NEWLINK:
		previous = m.links[attrs.Index]
		if previous != nil && previous.Attrs().Name == attrs.Name {
			m.links[attrs.Index] = update.Link
			m.mu.Unlock()
			return
		}
		m.links[attrs.Index] = update.Link
	case unix.RTM_DELLINK:
		if old := m.links[attrs.Index]; old != nil {
			update.Link = old
			attrs = old.Attrs()
		}
		delete(m.links, attrs.Index)
	default:
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	if previous != nil && update.Header.Type == unix.RTM_NEWLINK {
		oldName := previous.Attrs().Name
		for _, callback := range callbacks {
			matchedOld, oldErr := path.Match(callback.pattern, oldName)
			matchedNew, newErr := path.Match(callback.pattern, attrs.Name)
			if oldErr == nil && newErr == nil && matchedOld && !matchedNew && callback.delCallback != nil {
				callback.delCallback(previous)
			}
		}
	}
	for _, callback := range callbacks {
		matched, err := path.Match(callback.pattern, attrs.Name)
		if err != nil || !matched {
			continue
		}
		if update.Header.Type == unix.RTM_NEWLINK && callback.newCallback != nil {
			callback.newCallback(update.Link)
		}
		if update.Header.Type == unix.RTM_DELLINK && callback.delCallback != nil {
			callback.delCallback(update.Link)
		}
	}
	if onChange != nil {
		onChange()
	}
}

func (m *InterfaceManager) RegisterWithPattern(pattern string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) error {
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid interface pattern %q: %w", pattern, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	callbacks := callbackSet{
		pattern:     pattern,
		newCallback: newCallback,
		delCallback: delCallback,
	}
	listLinks := m.listLinks
	if listLinks == nil {
		listLinks = netlink.LinkList
	}
	links, err := listLinks()
	if err != nil {
		// Registration must survive a transient initial dump failure so a
		// later NEWLINK or subscription rebuild can still resolve the link.
		m.callbacks = append(m.callbacks, callbacks)
		return fmt.Errorf("list interfaces for pattern %q: %w", pattern, err)
	}
	for _, link := range links {
		m.links[link.Attrs().Index] = link
		if matched, _ := path.Match(pattern, link.Attrs().Name); matched && initCallback != nil {
			initCallback(link)
		}
	}
	m.callbacks = append(m.callbacks, callbacks)
	return nil
}

func (m *InterfaceManager) Register(ifname string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	if err := m.RegisterWithPattern(ifname, initCallback, newCallback, delCallback); err != nil {
		log.Errorf("register interface %q: %v", ifname, err)
	}
}

// SetChangeCallback sets the callback run after a link is added, deleted, or renamed.
func (m *InterfaceManager) SetChangeCallback(callback func()) {
	m.mu.Lock()
	m.onChange = callback
	m.mu.Unlock()
}

// SetResetCallback sets the callback run before links are rebuilt after a subscription failure.
func (m *InterfaceManager) SetResetCallback(callback func()) {
	m.mu.Lock()
	m.onReset = callback
	m.mu.Unlock()
}

// Close stops the monitor and waits for any callback already in progress.
func (m *InterfaceManager) Close() error {
	m.stopSubscription()
	<-m.done
	return nil
}
