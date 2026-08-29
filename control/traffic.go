/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common/stats"
	"github.com/prometheus/client_golang/prometheus"
)

func openTrafficConnection(labels prometheus.Labels) *stats.TrafficConnection {
	return stats.DefaultTrafficTracker.Open(stats.TrafficIdentity{
		NodeID:   labels["id"],
		Outbound: labels["outbound"],
		Subtag:   labels["subtag"],
		Dialer:   labels["dialer"],
		Network:  labels["network"],
	})
}
