// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"reflect"
	"slices"

	"github.com/daeuniverse/dae/config"
)

// PreparedRules contains only validated rule data. Loading external rule files
// does not require a BPF generation or any running business instance.
type PreparedRules struct{ rules preparedRules }

func PrepareRules(ctx context.Context, routing *config.Routing, rules config.Rules, dirs []string) (*PreparedRules, error) {
	prepared, err := prepareRoutingRules(ctx, routing, dirs)
	if err == nil {
		err = prepared.enableFlowRules(ctx, rules, dirs)
	}
	if err != nil {
		return nil, err
	}
	return &PreparedRules{rules: prepared}, nil
}

func (p *PreparedRules) Equal(other *PreparedRules) bool {
	return p != nil && other != nil && reflect.DeepEqual(p.rules, other.rules)
}

func (p *PreparedRules) copy() preparedRules {
	rules := p.rules
	rules.destinations = slices.Clone(rules.destinations)
	if rules.capture != nil {
		rules.capture = new(*rules.capture)
	}
	return rules
}
