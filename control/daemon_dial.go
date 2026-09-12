// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
)

// Internal requests have the daemon's process identity and no client/interface.
func daemonProcessIdentity() bpfRoutingResult {
	name, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		name = []byte(filepath.Base(os.Args[0]))
	}
	identity := bpfRoutingResult{Pid: uint32(os.Getpid())}
	copy(identity.Pname[:], strings.TrimSpace(string(name)))
	return identity
}

// DNSResolverDialer uses the same destination, flow and routing decision as
// daemon downloads, and the DNS transport's existing leases/accounting. Only
// internal resolver traffic enters here; it publishes no client DNS evidence.
func (c *ControlPlane) DNSResolverDialer() netutils.ResolverDialContext {
	identity := daemonProcessIdentity()
	return func(parent context.Context, network string, server netip.AddrPort) (net.Conn, error) {
		if network != "udp" && network != "tcp" {
			return nil, net.UnknownNetworkError(network)
		}
		ctx, cancel := context.WithCancel(parent)
		defer cancel()
		if c.ctx != nil {
			stop := context.AfterFunc(c.ctx, cancel)
			defer stop()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		option, err := c.selectRoutedAddress(network, netip.AddrPort{}, identity, "", server)
		if err != nil {
			return nil, err
		}
		if option.Outbound.Name == consts.OutboundBlock.String() {
			return nil, errors.New("internal DNS destination blocked by routing")
		}
		return c.dialDNSUpstream(ctx, network, option, identity)
	}
}
