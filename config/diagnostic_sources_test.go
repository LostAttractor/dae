// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// Reformatting changes diagnostic file positions, not configuration semantics.
var ignoreRuleSources = cmpopts.IgnoreFields(config_parser.RoutingRule{}, "Sources")

func sameConfiguration(a, b any) bool { return cmp.Equal(a, b, ignoreRuleSources) }
