// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"net"

	"github.com/daeuniverse/dae/common/netutils"
	outbound "github.com/daeuniverse/dae/pkg/outbound/common"
)

// InstallDefaultResolver runs once during single-threaded process startup,
// before libraries can resolve hostnames. Reloads only change resolver policy.
func InstallDefaultResolver(mark uint32, server string) (*netutils.InternalResolver, error) {
	resolver, err := netutils.NewInternalResolver(mark, server)
	if err != nil {
		return nil, err
	}
	net.DefaultResolver = resolver.Resolver
	outbound.BootstrapResolver = resolver.Bootstrap
	return resolver, nil
}
