package shadowsocks

import (
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

func (c *TCPConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *UdpConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

// Invalid encrypted frames belong to this proxy stream or datagram; they do
// not invalidate a multiplexed transport carrying other proxy connections.
func responseFailure(err error, scope netproxy.FailureScope) error {
	reason := netproxy.ReasonProtocol
	if err == protocol.ErrFailAuth || err == protocol.ErrReplayAttack {
		reason = netproxy.ReasonAuth
	}
	return netproxy.WrapFailure(err, netproxy.Failure{Scope: scope, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Reason: reason, Phase: netproxy.OpRead})
}
