// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

func TestBorrowedGroupStartupPolicyIsCandidateLocal(t *testing.T) {
	runtime := NewRuntime()
	build := func(async bool) (*outbound.DialerGroup, bool) {
		t.Helper()
		conf := outboundUsageConfig(t, fmt.Sprintf(`global {}
node { one: 'socks5://127.0.0.1:1080' }
group { stable {
 node(one)
 policy: selector
 check_async: %t
} }
routing { fallback: stable }`, async))
		ctx, cancel := context.WithCancel(t.Context())
		core := &controlPlaneCore{closed: ctx, bpf: &BPFState{Runtime: runtime}}
		builder, err := core.buildOutbounds(t.Context(), outboundUsageNodes(conf), conf.Group, &conf.Routing, &conf.Global, consts.OutboundBlock)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); _ = builder.close() })
		critical := make([]bool, len(builder.outbounds))
		index := builder.nameToID["stable"]
		critical[index] = true
		policy := configureOutboundChecks(builder.outbounds, conf.Group, critical)
		return builder.outbounds[index], policy[index]
	}
	first, firstAsync := build(true)
	if !firstAsync {
		t.Fatal("fixture did not configure initial async group")
	}
	next, nextAsync := build(false)
	if next != first {
		t.Fatal("fixture did not reuse the same group")
	}
	if nextAsync || !firstAsync {
		t.Fatal("new explicit check_async:false was ignored by borrowed group")
	}
}
