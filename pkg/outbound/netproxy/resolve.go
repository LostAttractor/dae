package netproxy

import (
	"context"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/common"
)

// ResolveUDPAddr uses the physical entry's resolver when available. Proxy
// layers deliberately don't forward it: later hops keep bootstrap semantics.
func ResolveUDPAddr(ctx context.Context, dialer Dialer, address string) (*net.UDPAddr, error) {
	if resolver, ok := dialer.(interface {
		ResolveUDPAddr(context.Context, string) (*net.UDPAddr, error)
	}); ok {
		return resolver.ResolveUDPAddr(ctx, address)
	}
	return common.ResolveUDPAddrContext(ctx, common.BootstrapResolver, "ip", address)
}
