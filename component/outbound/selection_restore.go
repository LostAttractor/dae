// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import "github.com/daeuniverse/dae/common/selector"

// ResolveSelection maps a saved logical path to a current runtime ID. Identical
// repeated paths are equivalent for a manual selector; scoring does not apply.
func (g *DialerGroup) ResolveSelection(saved *selector.Path) (id, status string) {
	if saved == nil {
		return "", ""
	}
	for _, exact := range []bool{true, false} {
		var found *selector.Path
		for _, d := range g.Dialers {
			path := d.SelectionReference()
			if !saved.Matches(path, exact) {
				continue
			}
			if found != nil && !found.Matches(path, true) {
				return "", "ambiguous"
			}
			if found == nil {
				found, id = path, d.StatsID()
			}
		}
		if found != nil {
			return id, "matched"
		}
	}
	return "", "missing"
}
