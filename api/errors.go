// SPDX-License-Identifier: AGPL-3.0-only

package api

import "errors"

// Runtime operation errors are independent of their HTTP status mapping.
var (
	ErrSelectorNotFound  = errors.New("selector group not found")
	ErrSelectorNode      = errors.New("node_id is not a path in this selector")
	ErrSelectorNoDefault = errors.New("selector has no configured default")
	ErrProbeOutbound     = errors.New("probe outbound not found")
	ErrProbeNode         = errors.New("node_id is not a path in this outbound")
	ErrProbeUnsupported  = errors.New("outbound does not support connectivity probes")
	ErrOperationsBusy    = errors.New("operation queue is full, a resource refresh is pending, or process replacement is in progress")
	ErrOperationsClosed  = errors.New("daemon is stopping")
	ErrOperationInvalid  = errors.New("invalid operation kind or abort option")
)
