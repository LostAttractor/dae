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
	return c.settings.Reload(func(current, next settings.Snapshot) error {
		return c.applyRuntimeSettings(current, next, func() error { return nil })
	})
}

// API edits and file reloads share the same live-state update and rollback path.
// The caller holds settingsMu; the store holds its write lock through persist.
func (c *ControlPlane) applyRuntimeSettings(current, next settings.Snapshot, persist func() error) error {
	changed := make(map[[6]byte]bool)
	sets := c.routingState.ClientSets()
	for _, name := range sets {
		before, after := current.Members(name), next.Members(name)
		for _, mac := range before {
			if !slices.Contains(after, mac) {
				changed[mac] = true
			}
		}
		for _, mac := range after {
			if !slices.Contains(before, mac) {
				changed[mac] = true
			}
		}
	}
	return c.changeDeviceRoutes(changed, func(commit func() error) error {
		apply := func() (err error) {
			var rollback []func() error
			defer func() {
				if err != nil {
					for _, undo := range slices.Backward(rollback) {
						err = errors.Join(err, undo())
					}
				}
			}()
			for _, name := range c.clientSets() {
				previous, members := current.Members(name), next.Members(name)
				if slices.Equal(previous, members) {
					continue
				}
				if err := c.setClientMembers(name, previous, members); err != nil {
					return err
				}
				rollback = append(rollback, func() error {
					return c.setClientMembers(name, members, previous)
				})
			}
			if err := persist(); err != nil {
				return err
			}
			return commit()
		}
		// Each group holds its selection until later changes have committed;
		// errors unwind all tentative choices without issuing close signals.
		for _, group := range slices.Backward(c.outbounds) {
			if !group.IsSelector() || current.Selectors[group.Name] == next.Selectors[group.Name] {
				continue
			}
			rest := apply
			apply = func() error { return group.ChangeSelection(next.Selectors[group.Name], rest) }
		}
		return apply()
	})
}

// Restore before checks/downloads, and once more after draining the old API on
// reload. Building a candidate must not erase the active plane's saved choices.
func (c *ControlPlane) restoreRuntimeSettings(prune bool) error {
	stale := make(map[string]string)
	for _, group := range c.outbounds {
		if c.borrowedOutbounds[group] {
			continue
		}
		if !group.IsSelector() {
			continue
		}
		id := c.settings.Selection(group.Name)
		missing := id != "" && !slices.ContainsFunc(group.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == id })
		if missing {
			if prune {
				log.WithFields(log.Fields{"group": group.Name, "node_id": id}).Warn("Saved selector path disappeared; using the startup choice")
				stale[group.Name] = id
			}
			id = ""
		}
		if err := group.SetSelection(id); err != nil {
			return fmt.Errorf("restore selector %q: %w", group.Name, err)
		}
	}
	if err := c.restoreClientSets(); err != nil {
		return err
	}
	// Shared preferences change only after all candidate projections succeed.
	// A failed save leaves both disk and the active plane's store unchanged.
	if len(stale) != 0 {
		if err := c.settings.PruneSelections(stale); err != nil {
			return fmt.Errorf("prune disappeared selector paths: %w", err)
		}
	}
	return nil
}

func (c *ControlPlane) restoreClientSets() error {
	for _, name := range c.routingState.ClientSets() {
		members := c.settings.Members(name)
		if err := c.routingState.SetClientMembers(c.routingMatcher, name, members, c.kernelReady); err != nil {
			return err
		}
	}
	return nil
}
