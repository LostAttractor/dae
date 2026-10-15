// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"fmt"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func (r *Router) Explain(ctx context.Context, input api.ExplainRequest) plugin.Explanation {
	result := r.policy.Explain(ctx, input, r.upstreamNames)
	if r.prefer != 0 {
		result.Steps = append(result.Steps, api.ExplainStep{ID: "family_preference", Stage: "dns_family", Expression: fmt.Sprintf("preferred qtype %d", r.prefer), Status: "conditional", Match: "unknown", Reason: "suppression_depends_on_preferred_answer"})
	}
	return result
}
