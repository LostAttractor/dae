// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

type ResourceRefreshStatus struct {
	Operation *Operation `json:"operation,omitempty"`
	NextCheck time.Time  `json:"next_check,omitzero"`
}
