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

// httpRoutePlanner retains ingress identity and an optional inspection route.
// MITM binds unchanged requests to the original URL target and retains that plan
// for the connection. Explicit URL rewrites and auxiliary requests select their
// own immutable routes. Request.Host never changes the network target.
type httpRoutePlanner struct {
	plane       *ControlPlane
	network     string
	original    httpTarget
	source      netip.AddrPort
	destination netip.AddrPort
	identity    bpfRoutingResult
	retained    *DialOption
}

func (c *ControlPlane) mitmUpstreamPlanner(network, host string, source, destination netip.AddrPort, identity bpfRoutingResult, retained *DialOption) mitm.UpstreamPlanner {
	original, _ := parseHTTPTarget(net.JoinHostPort(host, fmt.Sprint(destination.Port())))
	planner := &httpRoutePlanner{
		plane: c, network: network, original: original,
		source: source, destination: destination, identity: identity, retained: retained,
	}
	return planner.plan
}

func (p *httpRoutePlanner) plan(request *http.Request) (mitm.UpstreamPlan, error) {
	ctx := request.Context()
	if err := ctx.Err(); err != nil {
		return mitm.UpstreamPlan{}, err
	}
	target, err := requestHTTPTarget(request)
	if err != nil {
		return mitm.UpstreamPlan{}, err
	}
	options, err := p.routeOptions(ctx, target)
	if err != nil {
		return mitm.UpstreamPlan{}, err
	}
	return p.upstreamPlan(request.URL.Scheme, target, options)
}

func (p *httpRoutePlanner) routeOptions(ctx context.Context, target httpTarget) ([]*DialOption, error) {
	if target == p.original {
		if p.retained != nil {
			return []*DialOption{p.retained}, nil
		}
		// Keep the intercepted IP for the original authority instead of
		// resolving the hostname to a different endpoint.
		domain := target.host
		if _, err := netip.ParseAddr(domain); err == nil {
			domain = ""
		}
		option, err := p.plane.selectRoutedAddress(p.network, p.source, p.identity, domain, p.destination)
		if err != nil {
			return nil, err
		}
		return []*DialOption{option}, nil
	}

	var options []*DialOption
	var failures []error
	for option, err := range p.plane.httpRouteCandidates(ctx, p.network, target, p.source, p.identity) {
		if err != nil {
			failures = append(failures, err)
			continue
		}
		options = append(options, option)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(options) == 0 {
		return nil, fmt.Errorf("HTTP target %s has no route: %w", target, errors.Join(failures...))
	}
	return options, nil
}

func (p *httpRoutePlanner) upstreamPlan(scheme string, target httpTarget, options []*DialOption) (mitm.UpstreamPlan, error) {
	if options[0].Outbound.Name == consts.OutboundBlock.String() {
		return mitm.UpstreamPlan{}, fmt.Errorf("HTTP upstream blocked by routing")
	}
	var key strings.Builder
	fmt.Fprintf(&key, "%q/%q", scheme, target.String())
	for _, option := range options {
		if cause := option.PolicyLease.AbortCause(); cause != nil {
			return mitm.UpstreamPlan{}, cause
		}
		fmt.Fprintf(&key, "/%q/%p/%d/%q/%s/%t/%p", option.Outbound.Name, option.Dialer, option.Mark, option.DialTarget, option.NetworkType.String(), option.OriginalOutbound != nil, option.PolicyLease)
	}
	c, source := p.plane, p.source
	plan := mitm.UpstreamPlan{Key: key.String(), Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var failures []error
		for _, option := range options {
			if err := ctx.Err(); err != nil {
				return nil, err
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
	if target == p.original {
		// The original plan is pinned even if its first dial fails. Keep its
		// policy revocation observable without requiring a successful socket.
		plan.Check = options[0].PolicyLease.AbortCause
	}
	if p.network == "udp" {
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
