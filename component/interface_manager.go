/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"errors"
	"fmt"
	"net"
	"path"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type callbackSet struct {
	pattern     string
	exact       bool
	newCallback func(netlink.Link)
	delCallback func(netlink.Link)
	active      *atomic.Bool
}

type callbackDelivery struct {
	callbacks []func() error
	done      chan<- error
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

	deliveryMu       sync.Mutex
	deliveryCond     *sync.Cond
	deliveryQueue    []*callbackDelivery
	deliveryStopping bool
	deliveryDone     chan struct{}
}

type linkSubscribeFunc func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error
type linkListFunc func() ([]netlink.Link, error)

const interfaceSubscribeRetryInterval = time.Second

func NewInterfaceManager() (*InterfaceManager, error) {
	return newInterfaceManager(netlink.LinkSubscribeWithOptions)
}

func newInterfaceManager(subscribe linkSubscribeFunc) (*InterfaceManager, error) {
	mgr := &InterfaceManager{
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		links:        make(map[int]netlink.Link),
		listLinks:    netlink.LinkList,
		deliveryDone: make(chan struct{}),
	}
	mgr.deliveryCond = sync.NewCond(&mgr.deliveryMu)

	ch, err := mgr.subscribe(subscribe)
	if err != nil {
		mgr.stopSubscription()
		return nil, fmt.Errorf("subscribe to link updates: %w", err)
	}

	go mgr.dispatchCallbacks()
	go mgr.monitor(ch, subscribe, netlink.LinkList)
	return mgr, nil
}

func (m *InterfaceManager) subscribe(subscribe linkSubscribeFunc) (chan netlink.LinkUpdate, error) {
	ch := make(chan netlink.LinkUpdate)
	// Existing links are loaded during registration and after resubscription.
	// ListExisting would broadcast its dump request to other link subscribers.
	err := subscribe(ch, m.stop, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			select {
			case <-m.stop:
				return
			default:
			}
			log.Warn("LinkSubscribe: ", err)
		},
	})
	return ch, err
}

func (m *InterfaceManager) stopSubscription() {
	m.closeOnce.Do(func() { close(m.stop) })
}

func runCallbackDelivery(delivery *callbackDelivery) error {
	for _, callback := range delivery.callbacks {
		if err := callback(); err != nil {
			return err
		}
	}
	return nil
}

func (m *InterfaceManager) dispatchCallbacks() {
	defer close(m.deliveryDone)
	for {
		m.deliveryMu.Lock()
		for len(m.deliveryQueue) == 0 && !m.deliveryStopping {
			m.deliveryCond.Wait()
		}
		if len(m.deliveryQueue) == 0 {
			m.deliveryMu.Unlock()
			return
		}
		delivery := m.deliveryQueue[0]
		m.deliveryQueue[0] = nil
		m.deliveryQueue = m.deliveryQueue[1:]
		m.deliveryMu.Unlock()

		err := runCallbackDelivery(delivery)
		if delivery.done != nil {
			delivery.done <- err
		}
	}
}

// enqueueDelivery preserves callback order without running callbacks under
// the manager lock. A nil dispatcher is supported by small unit-test managers.
func (m *InterfaceManager) enqueueDelivery(callbacks []func() error, done chan<- error) bool {
	if len(callbacks) == 0 {
		if done != nil {
			done <- nil
		}
		return true
	}
	if m.deliveryCond == nil {
		if done != nil {
			done <- runCallbackDelivery(&callbackDelivery{callbacks: callbacks})
		} else {
			_ = runCallbackDelivery(&callbackDelivery{callbacks: callbacks})
		}
		return true
	}
	m.deliveryMu.Lock()
	defer m.deliveryMu.Unlock()
	if m.deliveryStopping {
		if done != nil {
			done <- net.ErrClosed
		}
		return false
	}
	m.deliveryQueue = append(m.deliveryQueue, &callbackDelivery{callbacks: callbacks, done: done})
	m.deliveryCond.Signal()
	return true
}

func (m *InterfaceManager) stopCallbackDispatcher() {
	if m.deliveryCond == nil {
		return
	}
	m.deliveryMu.Lock()
	m.deliveryStopping = true
	m.deliveryCond.Broadcast()
	m.deliveryMu.Unlock()
	<-m.deliveryDone
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate, subscribe linkSubscribeFunc, listLinks linkListFunc) {
	defer func() {
		m.stopCallbackDispatcher()
		close(m.done)
	}()
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
	sortLinks(previous)
	current := make([]netlink.Link, 0, len(links))
	m.links = make(map[int]netlink.Link, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		m.links[link.Attrs().Index] = link
		current = append(current, link)
	}
	sortLinks(current)
	callbacks := append([]callbackSet(nil), m.callbacks...)
	onReset := m.onReset
	onChange := m.onChange
	delivery := make([]func() error, 0, len(previous)+len(current)+2)
	if onReset != nil {
		delivery = append(delivery, voidCallback(onReset))
	}
	for _, link := range previous {
		delivery = append(delivery, lifecycleCallbacks(callbacks, unix.RTM_DELLINK, link)...)
	}
	for _, link := range current {
		delivery = append(delivery, lifecycleCallbacks(callbacks, unix.RTM_NEWLINK, link)...)
	}
	if onChange != nil {
		delivery = append(delivery, voidCallback(onChange))
	}
	done := make(chan error, 1)
	hasDispatcher := m.deliveryCond != nil
	if hasDispatcher {
		m.enqueueDelivery(delivery, done)
	}
	m.mu.Unlock()
	if !hasDispatcher {
		m.enqueueDelivery(delivery, done)
	}
	<-done
}

func (m *InterfaceManager) handleLinkUpdate(update netlink.LinkUpdate) {
	if update.Link == nil || update.Link.Attrs() == nil {
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
	delivery := make([]func() error, 0, len(callbacks)+1)
	if previous != nil && update.Header.Type == unix.RTM_NEWLINK {
		oldName := previous.Attrs().Name
		for _, callback := range callbacks {
			if callbackMatches(callback, oldName) && !callbackMatches(callback, attrs.Name) && callback.delCallback != nil {
				delivery = append(delivery, linkCallback(callback, callback.delCallback, previous))
			}
		}
	}
	delivery = append(delivery, lifecycleCallbacks(callbacks, update.Header.Type, update.Link)...)
	if onChange != nil {
		delivery = append(delivery, voidCallback(onChange))
	}
	done := make(chan error, 1)
	hasDispatcher := m.deliveryCond != nil
	if hasDispatcher {
		m.enqueueDelivery(delivery, done)
	}
	m.mu.Unlock()
	if !hasDispatcher {
		m.enqueueDelivery(delivery, done)
	}
	<-done
}

func (m *InterfaceManager) RegisterWithPattern(pattern string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) error {
	var initial func(netlink.Link) error
	if initCallback != nil {
		initial = func(link netlink.Link) error {
			initCallback(link)
			return nil
		}
	}
	return m.register(pattern, false, initial, newCallback, delCallback, false)
}

// RegisterWithPatternSync waits for every initial callback and returns its
// first error. It must not be called from an interface callback.
func (m *InterfaceManager) RegisterWithPatternSync(pattern string, initCallback func(netlink.Link) error, newCallback func(netlink.Link), delCallback func(netlink.Link)) error {
	return m.register(pattern, false, initCallback, newCallback, delCallback, true)
}

func (m *InterfaceManager) register(name string, exact bool, initCallback func(netlink.Link) error, newCallback func(netlink.Link), delCallback func(netlink.Link), synchronous bool) error {
	if !exact {
		if _, err := path.Match(name, ""); err != nil {
			return fmt.Errorf("invalid interface pattern %q: %w", name, err)
		}
	}
	m.mu.Lock()
	if m.isStopped() {
		m.mu.Unlock()
		return net.ErrClosed
	}
	registration := &atomic.Bool{}
	registration.Store(true)
	registered := callbackSet{
		pattern:     name,
		exact:       exact,
		newCallback: newCallback,
		delCallback: delCallback,
		active:      registration,
	}
	listLinks := m.listLinks
	if listLinks == nil {
		listLinks = netlink.LinkList
	}
	links, err := listLinks()
	if err != nil {
		if !synchronous {
			// Asynchronous registrations survive a transient initial dump failure
			// so later NEWLINK or subscription recovery can resolve the link.
			m.callbacks = append(m.callbacks, registered)
		}
		m.mu.Unlock()
		return fmt.Errorf("list interfaces for %q: %w", name, err)
	}
	sortLinks(links)
	initialLinks := make([]netlink.Link, 0, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		m.links[link.Attrs().Index] = link
		if callbackMatches(registered, link.Attrs().Name) && initCallback != nil {
			initialLinks = append(initialLinks, link)
		}
	}
	m.callbacks = append(m.callbacks, registered)
	delivery := make([]func() error, 0, len(initialLinks))
	for _, link := range initialLinks {
		link := link
		delivery = append(delivery, func() error {
			if err := initCallback(link); err != nil {
				registration.Store(false)
				return err
			}
			return nil
		})
	}
	var done chan error
	if synchronous {
		done = make(chan error, 1)
	}
	hasDispatcher := m.deliveryCond != nil
	if hasDispatcher {
		m.enqueueDelivery(delivery, done)
	}
	m.mu.Unlock()
	if !hasDispatcher {
		m.enqueueDelivery(delivery, done)
	}
	if !synchronous {
		return nil
	}
	if err := <-done; err != nil {
		m.disableRegistration(registration)
		return err
	}
	return nil
}

func (m *InterfaceManager) Register(ifname string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	var initial func(netlink.Link) error
	if initCallback != nil {
		initial = func(link netlink.Link) error {
			initCallback(link)
			return nil
		}
	}
	if err := m.register(ifname, true, initial, newCallback, delCallback, false); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Errorf("register interface %q: %v", ifname, err)
	}
}

// RegisterSync is the exact-name variant of RegisterWithPatternSync.
func (m *InterfaceManager) RegisterSync(ifname string, initCallback func(netlink.Link) error, newCallback func(netlink.Link), delCallback func(netlink.Link)) error {
	return m.register(ifname, true, initCallback, newCallback, delCallback, true)
}

func (m *InterfaceManager) disableRegistration(registration *atomic.Bool) {
	registration.Store(false)
	m.mu.Lock()
	for i := range m.callbacks {
		if m.callbacks[i].active == registration {
			m.callbacks = append(m.callbacks[:i], m.callbacks[i+1:]...)
			break
		}
	}
	m.mu.Unlock()
}

func (m *InterfaceManager) isStopped() bool {
	select {
	case <-m.stop:
		return true
	default:
		return false
	}
}

func sortLinks(links []netlink.Link) {
	sort.Slice(links, func(i, j int) bool {
		if links[i] == nil || links[i].Attrs() == nil {
			return false
		}
		if links[j] == nil || links[j].Attrs() == nil {
			return true
		}
		if links[i].Attrs().Name != links[j].Attrs().Name {
			return links[i].Attrs().Name < links[j].Attrs().Name
		}
		return links[i].Attrs().Index < links[j].Attrs().Index
	})
}

func callbackMatches(callback callbackSet, ifname string) bool {
	if callback.exact {
		return callback.pattern == ifname
	}
	matched, err := path.Match(callback.pattern, ifname)
	return err == nil && matched
}

func callbackActive(callback callbackSet) bool {
	return callback.active == nil || callback.active.Load()
}

func linkCallback(owner callbackSet, callback func(netlink.Link), link netlink.Link) func() error {
	return func() error {
		if callbackActive(owner) {
			callback(link)
		}
		return nil
	}
}

func lifecycleCallbacks(callbacks []callbackSet, typ uint16, link netlink.Link) []func() error {
	if link == nil || link.Attrs() == nil {
		return nil
	}
	delivery := make([]func() error, 0, len(callbacks))
	for _, callback := range callbacks {
		if !callbackMatches(callback, link.Attrs().Name) {
			continue
		}
		switch typ {
		case unix.RTM_NEWLINK:
			if callback.newCallback != nil {
				delivery = append(delivery, linkCallback(callback, callback.newCallback, link))
			}
		case unix.RTM_DELLINK:
			if callback.delCallback != nil {
				delivery = append(delivery, linkCallback(callback, callback.delCallback, link))
			}
		}
	}
	return delivery
}

func voidCallback(callback func()) func() error {
	return func() error {
		callback()
		return nil
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
