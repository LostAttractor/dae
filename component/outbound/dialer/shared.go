// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import "github.com/daeuniverse/dae/common/stats"

// SharesRuntime identifies aliases that cannot provide independent failover.
func (d *Dialer) SharesRuntime(other *Dialer) bool {
	return d.pathRuntime == other.pathRuntime
}

// CanShare reports whether the path still has live group members. Existing
// connection leases may outlive this admission state.
func (d *Dialer) CanShare() bool { return d.ctx.Err() == nil }

// Share creates another group-local member of the same configured path.
// A retired runtime cannot be resurrected, even while retained callers drain.
func (d *Dialer) Share(property *Property, statsScope string) (*Dialer, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return nil, false
	}
	return d.pathRuntime.newMember(property, statsScope), true
}

// Caller holds mu or is constructing an unpublished runtime.
func (d *pathRuntime) newMember(property *Property, statsScope string) *Dialer {
	key := makeStatsKey(property, statsScope)
	member := &Dialer{
		pathRuntime:  d,
		Property:     property,
		stats:        dialerStats{key: key, id: stats.NodeID(key)},
		checkEnabled: true,
	}
	d.members[member] = struct{}{}
	return member
}

func (d *pathRuntime) membersSnapshot() []*Dialer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	members := make([]*Dialer, 0, len(d.members))
	for member := range d.members {
		if member.active {
			members = append(members, member)
		}
	}
	return members
}
