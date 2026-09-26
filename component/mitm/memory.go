// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import "github.com/daeuniverse/dae/pkg/membuffer"

const defaultBufferMemoryLimit int64 = 256 << 20

// bodyMemory is the MITM policy: shared across instances and overlapping hosts.
// Other components supply their own budgets to membuffer.
var bodyMemory = membuffer.NewBudget(defaultBufferMemoryLimit)

func (o Options) bodyMemory() *membuffer.Budget {
	if o.BodyMemory != nil {
		return o.BodyMemory
	}
	return bodyMemory
}
