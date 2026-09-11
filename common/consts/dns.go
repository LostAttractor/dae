// SPDX-License-Identifier: AGPL-3.0-only

package consts

import "time"

const (
	// Connectivity probes may retry; transparent DNS relay uses only the bound.
	DefaultDNSRetryInterval = 5 * time.Second
	DefaultDNSRetryCount    = 3
	DefaultDNSTimeout       = DefaultDNSRetryInterval * DefaultDNSRetryCount
	// Collect expired domain evidence and reconcile the kernel projection.
	DnsStateSweepInterval = time.Minute
	// Full EDNS(0) payload capacity; never truncate to the link MTU.
	MaxDnsMessageSize = 1<<16 - 1
)
