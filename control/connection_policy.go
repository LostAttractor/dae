package control

import (
	"errors"

	"github.com/daeuniverse/outbound/netproxy"
)

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
