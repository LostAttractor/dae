// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"fmt"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// A group filter imports logical paths before runtime policy or address-family
// selection. Property filters therefore see complete paths, not individual hops.
func (c *GroupCompiler) compileFilterStage(owner *groupDefinition, functions []*config_parser.Function, annotation *dialer.Annotation, entry EntryOptions) (*compiledStage, error) {
	filters, families, err := splitEntryFilters(functions)
	if err != nil {
		return nil, err
	}
	entry.Families = families
	stage := &compiledStage{annotation: annotation, entry: entry}
	var properties []*config_parser.Function
	for _, filter := range filters {
		if filter.Name != "group" {
			properties = append(properties, filter)
			continue
		}
		if stage.group != nil {
			return nil, fmt.Errorf("a filter stage can reference only one group; use separate filter statements to combine groups")
		}
		if filter.Not || filter.Quoted || len(filter.Params) != 1 || filter.Params[0].Key != "" || strings.TrimSpace(filter.Params[0].Val) == "" {
			return nil, fmt.Errorf("group filter requires one exact group name without negation")
		}
		name := filter.Params[0].Val
		stage.group = c.byName[name]
		if stage.group == nil {
			return nil, fmt.Errorf("group(%q): group not found", name)
		}
		owner.dependencies = append(owner.dependencies, stage.group)
	}
	if stage.group != nil {
		stage.filters, err = compileFilters(properties, nil)
	} else {
		stage.nodes, err = c.set.Filter(properties)
		if families != nil {
			stage.nodes = slices.DeleteFunc(stage.nodes, func(node *NodeInfo) bool {
				return entryAddressFamilies(node.Property.Address)&*families == 0
			})
		}
	}
	if err != nil {
		return nil, err
	}
	return stage, nil
}

func pathFilterHit(path *PathSpec, filters []*compiledFilter) bool {
	for _, filter := range filters {
		var value string
		if filter.name == FilterInput_SubscriptionTag {
			// A path's subscription belongs to its terminal node, as in runtime
			// status. The remaining string properties describe the entire chain.
			value = path.Nodes[len(path.Nodes)-1].Property.SubscriptionTag
		} else {
			var builder strings.Builder
			for i, node := range path.Nodes {
				if i != 0 {
					builder.WriteString(" -> ")
				}
				builder.WriteString(node.filterValue(filter.name))
			}
			value = builder.String()
		}
		if !filter.matches(value) {
			return false
		}
	}
	return true
}
