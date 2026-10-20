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
	changes, affected := c.clientMembershipChanges(current, next)
	return c.changeDeviceRoutes(affected, func(commit func() error) error {
		apply := func() (err error) {
			var rollback []func() error
			defer func() {
				if err != nil {
					for _, undo := range slices.Backward(rollback) {
						err = errors.Join(err, undo())
					}
				}
			}()
			for _, change := range changes {
				if err := c.setClientMembers(change.name, change.previous, change.next); err != nil {
					return err
				}
				rollback = append(rollback, func() error {
					return c.setClientMembers(change.name, change.next, change.previous)
				})
			}
			return c.changeHTTPClients(current, next, persist, commit)
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

type clientMembershipChange struct {
	name           string
	previous, next [][6]byte
}

// Decode each changed set once for application and rollback. Only membership
// changes in routing sets invalidate device connections; export-only sets do not.
func (c *ControlPlane) clientMembershipChanges(current, next settings.Snapshot) ([]clientMembershipChange, map[[6]byte]bool) {
	var changes []clientMembershipChange
	affected := make(map[[6]byte]bool)
	for _, name := range c.clientSets() {
		if slices.Equal(current.Clients[name], next.Clients[name]) {
			continue
		}
		change := clientMembershipChange{name: name, previous: current.Members(name), next: next.Members(name)}
		changes = append(changes, change)
		if c.routingState == nil {
			continue
		}
		if _, routed := c.routingState.clientSetSlots[name]; !routed {
			continue
		}
		removed := make(map[[6]byte]bool, len(change.previous))
		for _, mac := range change.previous {
			removed[mac] = true
		}
		for _, mac := range change.next {
			if removed[mac] {
				delete(removed, mac)
			} else {
				affected[mac] = true
			}
		}
		for mac := range removed {
			affected[mac] = true
		}
	}
	return changes, affected
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
	if err := c.restoreClientSets(); err != nil {
		return err
	}
	return c.restoreHTTPClients()
}

func (c *ControlPlane) restoreClientSets() error {
	for _, name := range c.routingState.ClientSets() {
		members := c.settings.Members(name)
		if err := c.routingState.SetClientMembers(name, members, c.kernelReady); err != nil {
			return err
		}
	}
	return nil
}
