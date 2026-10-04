// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"slices"

	"github.com/daeuniverse/dae/component/clientset"
)

// Exported sets are usable without a dae routing rule. Description-only entries
// still require a routing reference before exposing a device self-service toggle.
func (c *ControlPlane) clientSets() []string {
	names := c.routingMatcherBuilder.ClientSets()
	for name, client := range c.clients {
		if client.IPSet != "" || client.NFTSet != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// Publish exports only on activation, after the previous API has drained.
// Candidate preparation must not change the active plane's netfilter sets.
func (c *ControlPlane) syncClientExports() error {
	for name, client := range c.clients {
		members := c.settings.Members(name)
		if err := clientset.Replace(client.IPSet, client.NFTSet, members); err != nil {
			return fmt.Errorf("initialize client %q: %w", name, err)
		}
	}
	return nil
}

// The caller holds settingsMu. Keep the routing matcher and external sets on
// the same accepted snapshot; persistence failures use this path to undo updates.
func (c *ControlPlane) setClientMembers(name string, previous, next [][6]byte) error {
	if err := c.routingMatcherBuilder.SetClientMembers(c.routingMatcher, name, next, c.kernelReady); err != nil {
		return err
	}
	if !c.kernelReady {
		return nil
	}
	client := c.clients[name]
	if err := clientset.Replace(client.IPSet, client.NFTSet, next); err != nil {
		err = errors.Join(err, c.routingMatcherBuilder.SetClientMembers(c.routingMatcher, name, previous, true))
		return fmt.Errorf("sync client %q: %w", name, err)
	}
	return nil
}
