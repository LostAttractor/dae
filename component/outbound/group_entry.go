// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import "fmt"

// Check definitions even when an earlier filter currently matches no nodes.
// Cycles have already been rejected by validateCycles.
func (c *GroupCompiler) validateEntryPositions() error {
	seen := make(map[*groupDefinition]bool)
	var visit func(*groupDefinition) (bool, error)
	visit = func(group *groupDefinition) (bool, error) {
		if hasEntry, ok := seen[group]; ok {
			return hasEntry, nil
		}
		hasEntry := false
		for pathIndex, path := range group.paths {
			for stageIndex, stage := range path {
				configured := stage.entry.configured()
				if stage.group != nil {
					nested, err := visit(stage.group)
					if err != nil {
						return false, err
					}
					configured = configured || nested
				}
				if configured && stageIndex != 0 {
					return false, fmt.Errorf("group %q path %d stage %d: mark, interface and ipversion are only allowed on the entry stage", group.config.Name, pathIndex+1, stageIndex+1)
				}
				hasEntry = hasEntry || configured
			}
		}
		seen[group] = hasEntry
		return hasEntry, nil
	}
	for _, group := range c.ordered {
		if _, err := visit(group); err != nil {
			return err
		}
	}
	return nil
}
