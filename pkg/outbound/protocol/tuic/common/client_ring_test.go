// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

type ringTestClient struct {
	resource netproxy.ResourceRef
	lease    *netproxy.Lease
	state    *netproxy.PoolState
	closed   bool
	onClose  func()
}

func (c *ringTestClient) BindPool(state *netproxy.PoolState, ref netproxy.ResourceRef, onClose func()) {
	c.state, c.resource, c.onClose = state, ref, onClose
}
func (c *ringTestClient) ConnectQUIC(ctx context.Context, dialer netproxy.Dialer, dial DialFunc) (*quic.Conn, error) {
	_, _, err := dial(ctx, dialer)
	return nil, err
}
func (c *ringTestClient) FailureCause() error { return c.lease.Cause() }
func (c *ringTestClient) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.lease != nil {
		c.lease.Invalidate(ErrClientClosed)
	}
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func TestClientRingCloseStopsAndClosesClients(t *testing.T) {
	client := new(ringTestClient)
	ring := NewClientRing(func(func(quic.StreamType, int64)) *ringTestClient { return client }, 0)
	ring.current = ring.insertAfterCurrent(&clientRingNode[*ringTestClient]{cli: client})

	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	if !client.closed || ring.current != nil || ring.ring.Len() != 0 {
		t.Fatalf("closed ring retained state: clientClosed=%v current=%v len=%d", client.closed, ring.current, ring.ring.Len())
	}
	if err := ring.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// A late cleanup callback may still hold the allocation mutex.
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if err := ring.Allocate(t.Context(), true, func(context.Context, *ringTestClient) error { return nil }); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("DialContextWithDialer after Close returned %v", err)
	}
}

func TestClientRingRejectsAllocationAfterMemberTermination(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		closeRing bool
	}{{"failed member", false}, {"closed ring", true}} {
		t.Run(scenario.name, func(t *testing.T) {
			ring := NewClientRing(func(func(quic.StreamType, int64)) *ringTestClient { return new(ringTestClient) }, 0)
			defer ring.Close()
			client := new(ringTestClient)
			ring.insertAfterCurrent(&clientRingNode[*ringTestClient]{cli: client})
			client.lease = netproxy.NewLease(client.resource)
			ring.state.Ready(client.resource)
			cause := errors.New("member failed during allocation")
			err := ring.tryNext(func(*clientRingNode[*ringTestClient]) error {
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
				want = ErrClientClosed
			}
			if !errors.Is(err, want) {
				t.Fatalf("allocation handed off a terminated member: got %v, want %v", err, want)
			}
		})
	}
}
func TestCapacityDoesNotEstablishConnectionOnDataPlane(t *testing.T) {
	created := 0
	r := NewClientRing(func(func(quic.StreamType, int64)) *ringTestClient { created++; return new(ringTestClient) }, 0)
	defer r.Close()
	err := r.tryNext(func(*clientRingNode[*ringTestClient]) error { t.Fatal("empty pool allocated a new member"); return nil })
	if !IsCapacityError(err) || created != 0 || !r.Snapshot().RecoveryRequired {
		t.Fatalf("err=%v created=%d state=%+v", err, created, r.Snapshot())
	}
}

func TestClientRingUsesOnlyBidirectionalCapacity(t *testing.T) {
	client := new(ringTestClient)
	var report func(quic.StreamType, int64)
	ring := NewClientRing(func(callback func(quic.StreamType, int64)) *ringTestClient {
		report = callback
		return client
	}, 0)
	defer ring.Close()
	if err := ring.Connect(t.Context(), nil, func(context.Context, netproxy.Dialer) (*quic.Transport, net.Addr, error) {
		client.lease = netproxy.NewLease(client.resource)
		client.state.Ready(client.resource)
		report(quic.StreamTypeBidi, 2)
		report(quic.StreamTypeUni, 0)
		return nil, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	allocated := 0
	allocate := func(context.Context, *ringTestClient) error { allocated++; return nil }
	if err := ring.Allocate(t.Context(), true, allocate); err != nil {
		t.Fatalf("unidirectional limit blocked bidirectional stream: %v", err)
	}
	report(quic.StreamTypeBidi, 0)
	report(quic.StreamTypeUni, 100)
	if err := ring.Allocate(t.Context(), true, allocate); !IsCapacityError(err) || allocated != 1 {
		t.Fatalf("unidirectional credit admitted bidirectional stream: err=%v allocations=%d", err, allocated)
	}
	if err := ring.Allocate(t.Context(), false, allocate); err != nil || allocated != 2 {
		t.Fatalf("stream credit blocked an allocation that opens no stream: err=%v allocations=%d", err, allocated)
	}
}
func TestReplenishmentKeepsHealthyMemberAvailable(t *testing.T) {
	r := NewClientRing(func(func(quic.StreamType, int64)) *ringTestClient { return new(ringTestClient) }, 0)
	defer r.Close()
	member := &clientRingNode[*ringTestClient]{cli: new(ringTestClient)}
	r.current = r.insertAfterCurrent(member)
	r.state.Ready(member.cli.resource)
	healthy := r.Snapshot()
	r.state.RequestCapacity(nil)
	started, release := make(chan struct{}), make(chan struct{})
	failed := errors.New("replacement handshake failed")
	done := make(chan error, 1)
	go func() {
		done <- r.Connect(t.Context(), nil, func(ctx context.Context, _ netproxy.Dialer) (*quic.Transport, net.Addr, error) {
			close(started)
			select {
			case <-release:
				return nil, nil, failed
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("replenishment did not start")
	}
	if !r.mu.TryLock() {
		close(release)
		<-done
		t.Fatal("handshake blocked healthy member allocation")
	}
	r.mu.Unlock()
	err := r.tryNext(func(node *clientRingNode[*ringTestClient]) error {
		if node != member {
			t.Fatal("allocated unready replacement")
		}
		return nil
	})
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, failed) {
		t.Fatalf("Connect = %v", err)
	}
	after := r.Snapshot()
	if !after.Accepting || !after.RecoveryRequired || after.UsableCapacity != 1 || after.ReadinessVersion != healthy.ReadinessVersion {
		t.Fatalf("replenishment failure invalidated healthy pool: before=%+v after=%+v", healthy, after)
	}
}
func TestClientRingCloseCancelsInFlightAllocation(t *testing.T) {
	r := NewClientRing(func(func(quic.StreamType, int64)) *ringTestClient { return new(ringTestClient) }, 0)
	node := &clientRingNode[*ringTestClient]{cli: new(ringTestClient)}
	r.current = r.insertAfterCurrent(node)
	r.state.Ready(node.cli.resource)
	// Model the allocation critical section waiting on the pool context.
	r.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case <-r.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close waited for allocation before canceling")
	}
	r.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
