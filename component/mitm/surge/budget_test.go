// SPDX-License-Identifier: AGPL-3.0-only

package surge

import "github.com/daeuniverse/dae/pkg/membuffer"

var testBodyMemory = membuffer.NewBudget(256 << 20)
