// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"reflect"
	"slices"

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
			if !group.IsSelector() || reflect.DeepEqual(current.Selectors[group.Name], next.Selectors[group.Name]) {
				continue
			}
			rest := apply
			id, _ := group.ResolveSelection(next.Selectors[group.Name])
			apply = func() error { return group.ChangeSelection(id, rest) }
		}
		return apply()
	})
}

// Restore before checks/downloads, and once more after draining the old API on
// reload. Missing references remain saved so a later reload can restore them.
func (c *ControlPlane) restoreRuntimeSettings(reportMissing bool) error {
	for _, group := range c.outbounds {
		if c.borrowedOutbounds[group] {
			continue
		}
		if !group.IsSelector() {
			continue
		}
		saved := c.settings.Selection(group.Name)
		id, status := group.ResolveSelection(saved)
		if reportMissing && saved != nil && status != "matched" {
			log.WithFields(log.Fields{"group": group.Name, "path": saved.String(), "status": status}).Warn("Saved selector path unavailable; retaining preference and temporarily using the startup choice")
		}
		if err := group.SetSelection(id); err != nil {
			return fmt.Errorf("restore selector %q: %w", group.Name, err)
		}
	}
	return c.restoreClientSets()
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
