// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
)

// ProcessIdentity is a logical routing identity, not a kernel PID exemption.
type ProcessIdentity struct {
	PID  uint32
	Name string
}

func CurrentProcessIdentity() ProcessIdentity {
	name := filepath.Base(os.Args[0])
	if comm, err := os.ReadFile("/proc/self/comm"); err == nil {
		name = strings.TrimSuffix(string(comm), "\n")
	}
	return ProcessIdentity{PID: uint32(os.Getpid()), Name: name}
}

func (p ProcessIdentity) routingResult() routingResult {
	identity := routingResult{Pid: p.PID, SourceOrigin: uint8(plugin.SourceLocal)}
	copy(identity.Pname[:], p.Name)
	return identity
}

// Internal requests have no client/interface identity.
func daemonProcessIdentity() routingResult { return CurrentProcessIdentity().routingResult() }

func (c *ControlPlane) daemonIdentity() routingResult {
	if c.processIdentity != nil {
		return c.processIdentity.routingResult()
	}
	return daemonProcessIdentity()
}

// DNSResolverDialer uses the same destination, flow and routing decision as
// daemon downloads, and the DNS transport's existing leases/accounting. Only
// internal resolver traffic enters here; it publishes no client DNS evidence.
func (c *ControlPlane) DNSResolverDialer() netutils.ResolverDialContext {
	identity := c.daemonIdentity()
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
		option, err := c.selectRoutedAddress(ctx, network, netip.AddrPort{}, identity, "", server)
		if err != nil {
			return nil, err
		}
		return c.dialDNSUpstream(ctx, network, option, identity)
	}
}
