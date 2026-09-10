// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import "github.com/daeuniverse/dae/pkg/membuffer"

const DefaultBufferMemoryLimit int64 = 256 << 20

// BodyMemory is the MITM policy: shared across instances and overlapping hosts.
// Other components supply their own budgets to membuffer.
var BodyMemory = membuffer.NewBudget(DefaultBufferMemoryLimit)
