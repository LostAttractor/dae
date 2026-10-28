// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"net"
	"sync"
)

// Admission keeps an accepted operation alive through host retirement.
// Release it after DNS handling or after the accepted protocol connection ends.
type Admission struct {
	host *Host
	once sync.Once
}

// Admit registers work before a caller releases its host-selection lock.
func (h *Host) Admit() (*Admission, error) {
	if h == nil {
		return &Admission{}, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, net.ErrClosed
	}
	h.requests.Add(1)
	return &Admission{host: h}, nil
}

func (a *Admission) Host() *Host { return a.host }

func (a *Admission) Context() context.Context {
	if a.host == nil {
		return context.Background()
	}
	return a.host.forceContext
}

func (a *Admission) Release() {
	if a != nil && a.host != nil {
		a.once.Do(a.host.requests.Done)
	}
}
