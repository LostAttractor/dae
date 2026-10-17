// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"

	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/settings"
)

func setTestClientMembers(store *settings.Store, name string, macs [][6]byte) error {
	return store.Update(func(next *settings.Snapshot) error {
		members := make([]string, len(macs))
		for i, mac := range macs {
			members[i] = net.HardwareAddr(mac[:]).String()
		}
		next.Clients[name] = members
		return nil
	}, nil)
}

func setTestMITM(store *settings.Store, mac [6]byte, enabled *bool) error {
	return store.Update(func(next *settings.Snapshot) error {
		key := net.HardwareAddr(mac[:]).String()
		if enabled == nil {
			delete(next.MITM, key)
		} else {
			next.MITM[key] = *enabled
		}
		return nil
	}, nil)
}

func setTestSelection(store *settings.Store, name string, path *selector.Path) error {
	return store.Update(func(next *settings.Snapshot) error {
		next.Selectors[name] = path.Clone()
		return nil
	}, nil)
}
