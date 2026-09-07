// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// FlowRule adds a control effect without selecting a routing outbound.
type FlowRule struct {
	Filter []*config_parser.Function
	Action consts.MatchAction
}
