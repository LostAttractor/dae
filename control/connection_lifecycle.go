// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"errors"
	"io"

	"github.com/daeuniverse/outbound/netproxy"
)

// closeInBackground starts cleanup without making control-plane shutdown wait
// for transports whose Close may block. It does not guarantee cleanup completion.
func closeInBackground(closer io.Closer) {
	if closer != nil {
		go func() { _ = closer.Close() }()
	}
}

func connectionAbortCause(leases ...*netproxy.Lease) error {
	var err error
	for _, lease := range leases {
		err = errors.Join(err, lease.AbortCause())
	}
	return err
}

// watchAbort observes an explicit termination instruction. Closing the watcher
// does not change the lease; the resource owner may still serve other relays.
func watchAbort(resource, policy, route *netproxy.Lease, abort func()) (stop func()) {
	if resource == nil && policy == nil && route == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		resourceDone, policyDone, routeDone := resource.Done(), policy.Done(), route.Done()
		for resourceDone != nil || policyDone != nil || routeDone != nil {
			select {
			case <-resourceDone:
				resourceDone = nil
			case <-policyDone:
				policyDone = nil
			case <-routeDone:
				routeDone = nil
			case <-done:
				return
			}
			if connectionAbortCause(resource, policy, route) != nil {
				abort()
				return
			}
		}
	}()
	return func() { close(done) }
}
