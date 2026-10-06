// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestConditionalPriorityIgnoresSelectionOffset(t *testing.T) {
	d := newUncheckedDialer(t, "path")
	annotation := &dialer.Annotation{ConditionalPriority: []*dialer.Priority{{Pri: 10, High: time.Second}}}
	g := newSelectorTestGroup(t, []*dialer.Dialer{d}, []*dialer.Annotation{annotation},
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, nil)
	for _, offset := range []time.Duration{-time.Hour, time.Hour} {
		annotation.AddLatency = offset
		candidate, ok := g.candidate(d, testNetworkType)
		if !ok || candidate.priority != 10 || candidate.sortingLatency != candidate.latency+offset {
			t.Fatalf("offset %v changed priority or was omitted from score: %+v", offset, candidate)
		}
	}
}
