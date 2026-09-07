// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
)

// Each final request gets an immutable plan before transport reuse. The same
// dial path handles both retained pure-inspection routes and new decisions.
func (c *ControlPlane) mitmUpstreamPlanner(network, host string, source, destination netip.AddrPort, identity bpfRoutingResult, retained *DialOption) mitm.UpstreamPlanner {
	original, _ := parseHTTPTarget(net.JoinHostPort(host, fmt.Sprint(destination.Port())))
	return func(request *http.Request) (mitm.UpstreamPlan, error) {
		ctx := request.Context()
		if err := ctx.Err(); err != nil {
			return mitm.UpstreamPlan{}, err
		}
		target, err := requestHTTPTarget(request)
		if err != nil {
			return mitm.UpstreamPlan{}, err
		}
		var options []*DialOption
		if target == original {
			option := retained
			if option == nil {
				// HTTP authority is known. Keep the intercepted IP instead of
				// resolving the original hostname to a different endpoint.
				domain := target.host
				if _, err := netip.ParseAddr(domain); err == nil {
					domain = ""
				}
				option, err = c.selectHTTPAddress(network, source, identity, domain, destination)
				if err != nil {
					return mitm.UpstreamPlan{}, err
				}
			}
			options = append(options, option)
		} else {
			var failures []error
			for option, err := range c.httpRouteCandidates(ctx, network, target, source, identity) {
				if err != nil {
					failures = append(failures, err)
					continue
				}
				options = append(options, option)
			}
			if err := ctx.Err(); err != nil {
				return mitm.UpstreamPlan{}, err
			}
			if len(options) == 0 {
				return mitm.UpstreamPlan{}, fmt.Errorf("HTTP target %s has no route: %w", target, errors.Join(failures...))
			}
		}
		if options[0].Outbound.Name == consts.OutboundBlock.String() {
			return mitm.UpstreamPlan{}, fmt.Errorf("HTTP upstream blocked by routing")
		}
		var key strings.Builder
		fmt.Fprintf(&key, "%q/%q", request.URL.Scheme, target.String())
		for _, option := range options {
			fmt.Fprintf(&key, "/%q/%p/%d/%q/%s/%t", option.Outbound.Name, option.Dialer, option.Mark, option.DialTarget, option.NetworkType.String(), option.OriginalOutbound != nil)
		}
		plan := mitm.UpstreamPlan{Key: key.String(), Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var failures []error
			for _, option := range options {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if option.Outbound.Name == consts.OutboundBlock.String() {
					return nil, fmt.Errorf("HTTP upstream blocked by routing")
				}
				conn, err := c.dialHTTPUpstream(ctx, option)
				logHTTPDial(source, target.host, option, err)
				if err == nil {
					return conn, nil
				}
				failures = append(failures, err)
			}
			return nil, errors.Join(failures...)
		}}
		if network == "udp" {
			plan.Dial = nil
			plan.DialPacket = func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
				var failures []error
				for _, option := range options {
					if err := ctx.Err(); err != nil {
						return nil, nil, err
					}
					if option.Outbound.Name == consts.OutboundBlock.String() {
						return nil, nil, fmt.Errorf("HTTP upstream blocked by routing")
					}
					conn, peer, err := c.dialHTTPPacketUpstream(ctx, option)
					logHTTPDial(source, target.host, option, err)
					if err == nil {
						return conn, peer, nil
					}
					failures = append(failures, err)
				}
				return nil, nil, errors.Join(failures...)
			}
		}
		return plan, nil
	}
}
