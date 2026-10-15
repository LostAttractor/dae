package tuic

import (
	"context"
	"errors"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"net"
	"testing"
	"time"
)

func TestCapacityDoesNotEstablishConnectionOnDataPlane(t *testing.T) {
	created := 0
	r := newClientRing(func(func(int64)) *clientImpl { created++; return new(clientImpl) }, 0)
	defer r.Close()
	err := r.tryNext(func(*clientRingNode) error { t.Fatal("empty pool allocated a new member"); return nil })
	if !common.IsCapacityError(err) || created != 0 || !r.Snapshot().RecoveryRequired {
		t.Fatalf("err=%v created=%d state=%+v", err, created, r.Snapshot())
	}
}
func TestReplenishmentKeepsHealthyMemberAvailable(t *testing.T) {
	r := newClientRing(func(func(int64)) *clientImpl { return new(clientImpl) }, 0)
	defer r.Close()
	member := &clientRingNode{cli: new(clientImpl), capability: -1}
	r.current = r._insertAfterCurrent(member)
	r.state.Ready(member.cli.resource)
	healthy := r.Snapshot()
	r.state.RequestCapacity()
	started, release := make(chan struct{}), make(chan struct{})
	failed := errors.New("replacement handshake failed")
	done := make(chan error, 1)
	go func() {
		done <- r.Connect(context.Background(), nil, func(ctx context.Context, _ netproxy.Dialer) (*quic.Transport, net.Addr, error) {
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
	err := r.tryNext(func(node *clientRingNode) error {
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
