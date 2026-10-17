// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"errors"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
)

// StartSampling starts traffic history sampling for the store and its devices.
// Only one sampler may run at a time. The returned stop function is idempotent
// and waits for the sampler to exit; a later start retains counters and history.
// Recording and reading statistics do not require a running sampler.
func (s *Store) StartSampling() (stop func(), err error) {
	s.samplerMu.Lock()
	defer s.samplerMu.Unlock()
	if s.samplerRunning {
		return nil, errors.New("traffic sampling already started")
	}
	s.samplerRunning = true
	ticker := time.NewTicker(api.TrafficHistoryInterval)
	stopping := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-stopping:
				return
			case <-ticker.C:
				s.sampleAt(time.Now())
			}
		}
	}()
	return sync.OnceFunc(func() {
		close(stopping)
		<-done
		s.samplerMu.Lock()
		s.samplerRunning = false
		s.samplerMu.Unlock()
	}), nil
}
