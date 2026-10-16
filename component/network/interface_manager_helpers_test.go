// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"errors"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func (m *InterfaceManager) RegisterWithPattern(pattern string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) error {
	var initial func(netlink.Link) error
	if initCallback != nil {
		initial = func(link netlink.Link) error {
			initCallback(link)
			return nil
		}
	}
	_, err := m.register(pattern, false, initial, newCallback, delCallback, false)
	return err
}

func (m *InterfaceManager) Register(ifname string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	var initial func(netlink.Link) error
	if initCallback != nil {
		initial = func(link netlink.Link) error {
			initCallback(link)
			return nil
		}
	}
	if _, err := m.register(ifname, true, initial, newCallback, delCallback, false); err != nil && !errors.Is(err, net.ErrClosed) {
		log.WithField("interface", ifname).WithError(err).
			Warn("Initial interface lookup failed; waiting for a later interface update")
	}
}

// Tests that assert lifecycle effects wait for the ordered dispatcher.
func (m *InterfaceManager) handleLinkUpdate(update netlink.LinkUpdate) {
	if done := m.queueLinkUpdate(update); done != nil {
		<-done
	}
}
