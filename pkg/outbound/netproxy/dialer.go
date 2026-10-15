package netproxy

import (
	"context"
	"net"
	"time"
)

var (
	DialTimeout = 8 * time.Second
)

func NewDialTimeoutContextFrom(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DialTimeout)
}

// Dialer establishes connections with one of two addressing semantics.
// DialContext binds the returned connection to one destination. ListenPacket
// opens a packet association whose ReadFrom and WriteTo calls carry per-packet
// addresses. Full-cone implementations may ignore address.
//
// Concrete connections may implement additional interfaces. Callers select an
// operation by its addressing semantics, not by inspecting those interfaces.
// Both methods must return when ctx is canceled.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, address string) (net.PacketConn, error)
}
