// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/internal/pluginctx"
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
	identity    routingResult
	retained    *DialOption
}

func (c *ControlPlane) mitmUpstreamPlanner(network, host string, source, destination netip.AddrPort, identity routingResult, retained *DialOption) mitm.UpstreamPlanner {
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
	if target == p.original {
		option, err := p.originalRoute(ctx)
		if err != nil {
			return mitm.UpstreamPlan{}, err
		}
		return p.upstreamPlan(request.URL.Scheme, target, option)
	}
	ctx, cancel := context.WithCancel(ctx)
	next, stop := iter.Pull2(p.plane.httpRouteCandidates(ctx, p.network, target, p.source, p.identity))
	closeCandidates := sync.OnceFunc(func() { cancel(); stop() })
	var failures []error
	var advance func() (mitm.UpstreamPlan, error)
	advance = func() (mitm.UpstreamPlan, error) {
		for {
			option, err, ok := next()
			if !ok {
				return mitm.UpstreamPlan{}, errors.Join(fmt.Errorf("HTTP target %s has no further route", target), errors.Join(failures...))
			}
			if err != nil {
				failures = append(failures, err)
				continue
			}
			plan, err := p.upstreamPlan(request.URL.Scheme, target, option)
			if err != nil {
				return mitm.UpstreamPlan{}, err
			}
			plan.Next, plan.Close = advance, closeCandidates
			return plan, nil
		}
	}
	plan, err := advance()
	if err != nil {
		closeCandidates()
	}
	return plan, err
}

func (p *httpRoutePlanner) originalRoute(ctx context.Context) (*DialOption, error) {
	if p.retained != nil && pluginctx.HTTPPolicy(ctx) == "" {
		return p.retained, nil
	}
	// Keep the intercepted IP for the original authority.
	domain := p.original.host
	if _, err := netip.ParseAddr(domain); err == nil {
		domain = ""
	}
	return p.plane.selectHTTPAddress(ctx, p.network, p.source, p.identity, domain, p.destination)
}

func (p *httpRoutePlanner) upstreamPlan(scheme string, target httpTarget, option *DialOption) (mitm.UpstreamPlan, error) {
	if option.Outbound.Name == consts.OutboundBlock.String() {
		return mitm.UpstreamPlan{}, fmt.Errorf("HTTP upstream blocked by routing")
	}
	if cause := option.PolicyLease.AbortCause(); cause != nil {
		return mitm.UpstreamPlan{}, cause
	}
	key := fmt.Sprintf("%q/%q/%q/%p/%d/%q/%s/%t/%p", scheme, target.String(), option.Outbound.Name, option.Dialer, option.Mark, option.DialTarget, option.NetworkType.String(), option.OriginalOutbound != nil, option.PolicyLease)
	source := p.source
	plan := mitm.UpstreamPlan{Key: key, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := dialHTTPUpstream(ctx, option)
		logHTTPDial(source, target.host, option, err)
		return conn, err
	}}
	if target == p.original {
		// The original plan is pinned even if its first dial fails. Keep its
		// policy revocation observable without requiring a successful socket.
		plan.Check = option.PolicyLease.AbortCause
	}
	if p.network == "udp" {
		plan.Dial = nil
		plan.DialPacket = func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
			conn, peer, err := dialHTTPPacketUpstream(ctx, option)
			logHTTPDial(source, target.host, option, err)
			return conn, peer, err
		}
	}
	return plan, nil
}
