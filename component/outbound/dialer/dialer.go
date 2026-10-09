/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

// Dialer is a group-local member of a shared physical path. Properties and
// statistics belong to this member; connectivity and transport belong to the path.
type Dialer struct {
	*pathRuntime
	*Property
	stats dialerStats
	// Member state is protected by the shared runtime's mu.
	group        *groupBinding
	checkEnabled bool
	selected     bool
	active       bool
	closed       bool
	closeOnce    sync.Once
}

func NewDialer(runtime *netproxy.Runtime, option *GlobalOption, property *Property, checksConnectivity bool, statsScope string) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	session := runtime.Session()
	path := &pathRuntime{
		GlobalOption:       option,
		Dialer:             runtime.Dialer(),
		name:               property.Name,
		runtime:            runtime,
		session:            session,
		checksConnectivity: checksConnectivity,
		checks:             pathChecks{wake: make(chan struct{}, 1)},
		statusRevision:     1,
		recovery:           recoveryProgress{Phase: RecoveryQueued},
		ctx:                ctx,
		cancel:             cancel,
		members:            make(map[*Dialer]struct{}),
	}
	d := path.newMember(property, statsScope)
	d.active = true
	if !checksConnectivity {
		if session == nil {
			d.recovery.Phase = RecoveryReady
		}
		d.health.phase = healthHealthy
		for i := range d.health.networks {
			d.health.networks[i] = networkSupported
		}
	}
	if session != nil {
		snapshot := session.Snapshot()
		if !checksConnectivity {
			if snapshot.Accepting {
				d.health.readiness = snapshot.ReadinessVersion
			} else {
				d.health.phase = healthUnhealthy
			}
		}
	}
	return d
}

func (d *pathRuntime) ChecksConnectivity() bool {
	return d.checksConnectivity
}
