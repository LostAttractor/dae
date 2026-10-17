// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"

	"github.com/daeuniverse/dae/common"
)

// CheckSocketMark lets reload reject a change before preparing resources. BPF
// preparation repeats this check under the same lifecycle lock before loading.
func (r *Runtime) CheckSocketMark(mark uint32) error {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	return r.checkSocketMark(mark)
}

func (r *Runtime) checkSocketMark(mark uint32) error {
	mark = common.EffectiveSoMarkFromDae(mark)
	if err := common.ValidateSoMarkFromDae(mark); err != nil {
		return err
	}
	if len(r.shared) != 0 && r.soMarkFromDae != mark {
		return fmt.Errorf("so_mark_from_dae (%#x -> %#x) cannot change on reload; restart dae to apply it", r.soMarkFromDae, mark)
	}
	return nil
}
