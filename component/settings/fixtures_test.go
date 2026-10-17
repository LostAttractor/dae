// SPDX-License-Identifier: AGPL-3.0-only

package settings

import (
	"fmt"
	"slices"

	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/common/selector"
)

// Convenience setters are test fixtures. Production edits use Update with
// their live-state publication and rollback callback.
func (s *Store) SetSelection(group string, path *selector.Path) error {
	if group == "" {
		return fmt.Errorf("selector name must not be empty")
	}
	return s.Update(func(next *Snapshot) error {
		if path == nil {
			delete(next.Selectors, group)
		} else {
			next.Selectors[group] = path.Clone()
		}
		return nil
	}, nil)
}

// SetMembers saves a complete set. Callers serialize read-modify-write operations.
func (s *Store) SetMembers(name string, macs [][6]byte) error {
	if name == "" {
		return fmt.Errorf("client set name must not be empty")
	}
	if len(macs) > maxClients {
		return fmt.Errorf("client set %q exceeds %d devices", name, maxClients)
	}
	members := make([]string, len(macs))
	for i, mac := range macs {
		if !macaddr.ValidClient(mac) {
			return fmt.Errorf("client MAC must be a nonzero unicast Ethernet address")
		}
		members[i] = macString(mac)
	}
	slices.Sort(members)
	for i := 1; i < len(members); i++ {
		if members[i] == members[i-1] {
			return fmt.Errorf("duplicate client MAC %q", members[i])
		}
	}
	return s.Update(func(next *Snapshot) error {
		if len(members) == 0 {
			delete(next.Clients, name)
		} else {
			next.Clients[name] = members
		}
		return nil
	}, nil)
}

// SetMITM saves a per-device override; nil restores the configuration.
func (s *Store) SetMITM(mac [6]byte, enabled *bool) error {
	if !macaddr.ValidClient(mac) {
		return fmt.Errorf("client MAC must be a nonzero unicast Ethernet address")
	}
	return s.Update(func(next *Snapshot) error {
		key := macString(mac)
		if enabled == nil {
			delete(next.MITM, key)
		} else {
			next.MITM[key] = *enabled
		}
		return nil
	}, nil)
}
