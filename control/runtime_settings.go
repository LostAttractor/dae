// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"slices"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/settings"
	log "github.com/sirupsen/logrus"
)

// ReloadRuntimeSettings updates the active plane without rebuilding modules or
// restarting connections. API writes use the same lock; a failed application
// rolls back earlier changes and keeps the store's last accepted state.
func (c *ControlPlane) ReloadRuntimeSettings() (bool, error) {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	return c.settings.Reload(func(current, next settings.Snapshot) (err error) {
		var rollback []func() error
		defer func() {
			if err != nil {
				for _, undo := range slices.Backward(rollback) {
					err = errors.Join(err, undo())
				}
			}
		}()
		for _, group := range c.outbounds {
			if !group.IsSelector() {
				continue
			}
			previous := group.Selection()
			if err := group.SetSelection(next.Selectors[group.Name]); err != nil {
				return fmt.Errorf("reload selector %q: %w", group.Name, err)
			}
			rollback = append(rollback, func() error { return group.SetSelection(previous) })
		}
		for _, name := range c.routingMatcherBuilder.ClientSets() {
			previous, members := current.Members(name), next.Members(name)
			if slices.Equal(previous, members) {
				continue
			}
			if err := c.routingMatcherBuilder.SetClientMembers(c.routingMatcher, name, members, c.apiActive); err != nil {
				return err
			}
			rollback = append(rollback, func() error {
				return c.routingMatcherBuilder.SetClientMembers(c.routingMatcher, name, previous, c.apiActive)
			})
		}
		return nil
	})
}

// Restore before checks/downloads, and once more after draining the old API on
// reload. Building a candidate must not erase the active plane's saved choices.
func (c *ControlPlane) restoreRuntimeSettings(prune bool) error {
	for _, group := range c.outbounds {
		if !group.IsSelector() {
			continue
		}
		id := c.settings.Selection(group.Name)
		missing := id != "" && !slices.ContainsFunc(group.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == id })
		if missing {
			if prune {
				log.WithFields(log.Fields{"group": group.Name, "node_id": id}).Warn("Saved selector path disappeared; restoring configuration")
				if err := c.settings.SetSelection(group.Name, ""); err != nil {
					return fmt.Errorf("reset selector %q: %w", group.Name, err)
				}
			}
			id = ""
		}
		if err := group.SetSelection(id); err != nil {
			return fmt.Errorf("restore selector %q: %w", group.Name, err)
		}
	}
	return c.restoreClientSets()
}

func (c *ControlPlane) restoreClientSets() error {
	for _, name := range c.routingMatcherBuilder.ClientSets() {
		members := c.settings.Members(name)
		if err := c.routingMatcherBuilder.SetClientMembers(c.routingMatcher, name, members, false); err != nil {
			return err
		}
	}
	return nil
}
