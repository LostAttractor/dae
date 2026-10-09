// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/internal/apiserver"
)

// The API queues work without waiting for publication, which drains API requests.
// The daemon loop serializes this work with reloads and cancels it on shutdown.
type resourceRefresher struct {
	requests chan struct{}
	mu       sync.Mutex
	status   api.ResourceRefreshStatus
}

func newResourceRefresher() *resourceRefresher {
	return &resourceRefresher{requests: make(chan struct{}, 1), status: api.ResourceRefreshStatus{State: "idle"}}
}

func (r *resourceRefresher) ResourceRefreshStatus() api.ResourceRefreshStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *resourceRefresher) busy() bool {
	return r.status.State == "queued" || r.status.State == "running"
}

func (r *resourceRefresher) RefreshResources() (api.ResourceRefreshStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy() {
		return r.status, apiserver.ErrRefreshBusy
	}
	r.status = api.ResourceRefreshStatus{Run: r.status.Run + 1, State: "queued", Trigger: "api", NextCheck: r.status.NextCheck}
	r.requests <- struct{}{}
	return r.status, nil
}

func (r *resourceRefresher) start(automatic bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if automatic {
		if r.busy() {
			return false
		}
		r.status = api.ResourceRefreshStatus{Run: r.status.Run + 1, Trigger: "automatic", NextCheck: r.status.NextCheck}
	}
	r.status.State, r.status.StartedAt = "running", time.Now()
	return true
}

func (r *resourceRefresher) finish(result string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.State, r.status.Result, r.status.FinishedAt = "completed", result, time.Now()
	if err != nil {
		r.status.State, r.status.Error = "failed", resource.RedactError(err).Error()
	}
}

func (r *resourceRefresher) setNext(next time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.NextCheck = next
}
