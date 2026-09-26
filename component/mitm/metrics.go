// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Metrics exposes the active host's registry to the process metrics endpoint.
// Its zero value is ready to use. Preparation never publishes collectors.
type Metrics struct {
	mu     sync.RWMutex
	active *prometheus.Registry
}

func (m *Metrics) Gather() ([]*dto.MetricFamily, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return nil, nil
	}
	return m.active.Gather()
}

func (m *Metrics) publish(registry *prometheus.Registry) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = registry
}

// retire joins in-flight collection before the host closes plugin resources.
// A retiring predecessor must not remove a successor's metrics.
func (m *Metrics) retire(registry *prometheus.Registry) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == registry {
		m.active = nil
	}
}
