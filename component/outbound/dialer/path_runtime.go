/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// pathRuntime owns a physical path shared by group-local Dialers. The last
// member stops checks; retained callers keep the transport alive while draining.
type pathRuntime struct {
	*GlobalOption
	netproxy.Dialer
	name               string
	runtime            *netproxy.Runtime
	session            netproxy.Session
	dormant            *dormantTransport
	checksConnectivity bool

	// mu protects members, health, checks, failures, recovery and lifetime state.
	mu             sync.RWMutex
	members        map[*Dialer]struct{}
	health         pathHealth
	checks         pathChecks
	failures       pathFailures
	recovery       recoveryProgress
	statusRevision uint64

	ctx           context.Context
	cancel        context.CancelFunc
	checkWG       sync.WaitGroup
	retireOnce    sync.Once
	retains       int
	proofHolds    int
	checksStopped bool
}

// Retain keeps the shared runtime accepting operations for an existing caller,
// even after its member closes. The final member stops checks; the final retain
// then retires the transport. Closed members reject new retains. Release is
// idempotent.
func (d *Dialer) Retain() (release func(), err error) {
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	d.retains++
	d.updateTransportDemandLocked()
	d.mu.Unlock()
	d.signalConnectivityCheck()
	return sync.OnceFunc(func() {
		d.mu.Lock()
		d.retains--
		d.updateTransportDemandLocked()
		retire := d.checksStopped && d.retains == 0
		d.mu.Unlock()
		d.signalConnectivityCheck()
		if retire {
			d.retireRuntime()
		}
	}), nil
}

// Close releases this member. The final member stops health checks; retained
// callers and established connection leases keep the transport alive to drain.
func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		delete(d.members, d)
		if len(d.members) != 0 {
			d.updateCheckDemandLocked()
			d.mu.Unlock()
			d.signalConnectivityCheck()
			return
		}
		d.cancel()
		d.recovery.Phase = RecoveryStopped
		d.recovery.RetryAt = time.Time{}
		d.statusRevision++
		d.mu.Unlock()
		d.checkWG.Wait()
		d.mu.Lock()
		d.checksStopped = true
		retire := d.retains == 0
		d.mu.Unlock()
		if retire {
			d.retireRuntime()
		}
	})
	return nil
}

func (d *pathRuntime) retireRuntime() {
	d.retireOnce.Do(func() {
		d.runtime.Retire()
		go func() {
			if err := d.runtime.Wait(context.Background()); err != nil {
				log.WithField("node", d.name).WithError(err).Debug("Outbound cleanup completed with an error")
			}
		}()
	})
}
