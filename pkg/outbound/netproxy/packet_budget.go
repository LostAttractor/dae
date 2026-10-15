package netproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// PacketBudget bounds active packet resources, including target streams opened
// inside a protocol association. It is supplied by the caller and shared across
// retained dialers and configuration generations. Closing resources retain their
// permits until Close returns; slow cleanup cannot bypass the admission limit.
type PacketBudget struct {
	limit int64
	used  atomic.Int64
}

func NewPacketBudget(limit int) *PacketBudget {
	if limit <= 0 {
		panic("packet budget must be positive")
	}
	return &PacketBudget{limit: int64(limit)}
}

type packetBudgetKey struct{}

func PacketBudgetFromContext(ctx context.Context) *PacketBudget {
	budget, _ := ctx.Value(packetBudgetKey{}).(*PacketBudget)
	return budget
}

func PacketCapacityError() error {
	return WrapFailure(errors.New("UDP packet resource capacity exhausted"), Failure{
		Scope: ScopeOperation, Layer: LayerUDP, Reason: ReasonCapacity, Origin: OriginLocalProtocol,
	})
}

// Open reserves before dialing and propagates the same budget to nested UDP
// resources. A nil budget preserves a standalone caller's admission policy.
func (b *PacketBudget) Open(ctx context.Context, address string, open func(context.Context, string) (net.PacketConn, error)) (net.PacketConn, error) {
	if b == nil {
		return open(ctx, address)
	}
	for {
		used := b.used.Load()
		if used >= b.limit {
			return nil, PacketCapacityError()
		}
		if b.used.CompareAndSwap(used, used+1) {
			break
		}
	}
	conn, err := open(context.WithValue(ctx, packetBudgetKey{}, b), address)
	if conn == nil {
		b.used.Add(-1)
		return nil, err
	}
	owned := &budgetPacketConn{PacketConn: conn, budget: b}
	if err != nil {
		go owned.Close()
		return nil, err
	}
	return owned, nil
}

type budgetPacketConn struct {
	net.PacketConn
	budget *PacketBudget
	once   sync.Once
	err    error
}

func (c *budgetPacketConn) DependencyLease() *Lease { return DependencyOf(c.PacketConn) }
func (c *budgetPacketConn) Close() error {
	c.once.Do(func() {
		c.err = c.PacketConn.Close()
		c.budget.used.Add(-1)
	})
	return c.err
}
