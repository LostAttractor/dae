// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/daeuniverse/dae/common/stats"
)

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
	var accounting *dialerStats
	for member := range d.members {
		if member.StatsKey() == key {
			accounting = member.stats
			break
		}
	}
	if accounting == nil {
		accounting = &dialerStats{key: key, id: stats.NodeID(key)}
	}
	member := &Dialer{
		pathRuntime:  d,
		Property:     property,
		stats:        accounting,
		linkDigest:   linkDigest(property.Link),
		checkEnabled: true,
	}
	d.members[member] = struct{}{}
	return member
}

// LinkDigest identifies the configured path. Links may carry credentials, so
// identities derived from them retain only this digest.
func (d *Dialer) LinkDigest() string { return d.linkDigest }

func linkDigest(link string) string {
	digest := sha256.Sum256([]byte(link))
	return hex.EncodeToString(digest[:])
}
