package juicity

import (
	"context"
	"errors"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
)

func TestClientRingCloseStopsAndClosesClients(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &clientImpl{ClientOption: &ClientOption{Ctx: ctx, Cancel: cancel}}
	ring := newClientRing(func(func(int64)) *clientImpl { return client }, 0)
	ring.current = ring._insertAfterCurrent(&clientRingNode{cli: client, capability: -1})

	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil || ring.current != nil || ring.ring.Len() != 0 {
		t.Fatalf("closed ring retained state: clientErr=%v current=%v len=%d", ctx.Err(), ring.current, ring.ring.Len())
	}
	if err := ring.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// A late cleanup callback may still hold the allocation mutex.
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if _, err := ring.DialContext(context.Background(), nil); !errors.Is(err, common.ErrClientClosed) {
		t.Fatalf("DialContext after Close returned %v", err)
	}
}

func TestClientRingRejectsAllocationAfterMemberTermination(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		closeRing bool
	}{{"failed member", false}, {"closed ring", true}} {
		t.Run(scenario.name, func(t *testing.T) {
			ring := newClientRing(func(func(int64)) *clientImpl { return newCapacityClient() }, 0)
			defer ring.Close()
			client := newCapacityClient()
			ring._insertAfterCurrent(&clientRingNode{cli: client, capability: -1})
			client.lease = netproxy.NewLease(client.resource)
			ring.state.Ready(client.resource)
			cause := errors.New("member failed during allocation")
			err := ring.tryNext(func(*clientRingNode) error {
				// Selection has completed, but ownership has not reached the caller.
				if scenario.closeRing {
					_ = ring.Close()
				} else {
					client.lease.Abort(cause)
					ring.state.Failed(client.resource, cause)
				}
				return nil
			})
			want := cause
			if scenario.closeRing {
				want = common.ErrClientClosed
			}
			if !errors.Is(err, want) {
				t.Fatalf("allocation handed off a terminated member: got %v, want %v", err, want)
			}
		})
	}
}
