// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func TestRuntimeRejectsSocketMarkChangeBeforeKernelPreparation(t *testing.T) {
	r := NewRuntime()
	// Represent a loaded generation without creating kernel resources: a
	// rejected candidate must return before touching any shared map or BPF API.
	r.shared = map[string]*ebpf.Map{"loaded": nil}
	r.soMarkFromDae = common.InternalSoMarkFromDae
	for _, mark := range []uint32{0, common.InternalSoMarkFromDae} {
		if err := r.CheckSocketMark(mark); err != nil {
			t.Fatalf("default alias rejected: %v", err)
		}
	}
	for _, mark := range []uint32{0x200, consts.TproxyMark} {
		err := r.CheckSocketMark(mark)
		if err == nil || !strings.Contains(err.Error(), "so_mark_from_dae") {
			t.Fatalf("changed/reserved mark accepted: %v", err)
		}
		_, prepareErr := prepareBPF(t.Context(), r, mark)
		if prepareErr == nil || prepareErr.Error() != err.Error() {
			t.Fatalf("early and publication checks disagree: %v / %v", err, prepareErr)
		}
	}
}
