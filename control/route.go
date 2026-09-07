// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/samber/oops"
)

type RouteParam struct {
	explicitTarget bool           // An explicit URL supplies a known name, or a literal IP with no name.
	destination    netip.AddrPort // Selected IP target; invalid until a rewrite or retained UDP target exists.
	routingResult  *bpfRoutingResult
	networkType    common.NetworkType
	Domain         string
	Src            netip.AddrPort
	Dest           netip.AddrPort // Input target of this attempt; destination matching never mutates it.
}

func (c *ControlPlane) RouteDialOption(ctx context.Context, p *RouteParam) (*DialOption, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !p.destination.IsValid() {
		var err error
		p.destination, err = c.routingMatcher.matchDestination(p)
		if err != nil {
			return nil, err
		}
	}
	decision, valid := kernelRoute(p.routingResult)
	targetRoute := p.destination.IsValid() || p.routingResult.CaptureFlags&(captureDestination|captureHTTPRequest) != 0
	captured := p.routingResult.CaptureFlags != 0
	// A pure HTTP capture does not invalidate a terminal kernel decision.
	if !targetRoute && captured && valid && (decision.outbound == consts.OutboundDirect || decision.outbound == consts.OutboundBlock) {
		decision.apply(p.routingResult)
		return c.selectDialOption(p, decision.outbound, decision.mark, false)
	}
	verified, shouldReroute, err := c.verifySniff(ctx, p.Dest, p.Domain)
	if err != nil {
		return nil, err
	}
	domain := p.Domain
	if !verified {
		domain = ""
	}
	if targetRoute {
		return c.routeDestination(p, domain)
	}
	if !valid || c.rerouteMode == consts.RerouteMode_Force || (c.rerouteMode == consts.RerouteMode_WhileNeed && shouldReroute) {
		if captured && !verified {
			return nil, fmt.Errorf("cannot preserve ambiguous DNS routing for %s without a trusted hostname", p.Dest.Addr())
		}
		decision.outbound, decision.mark, decision.must, err = c.Route(p.Src, p.Dest, domain, p.networkType.L4Proto.ToL4ProtoType(), p.routingResult)
		if err != nil {
			return nil, oops.Wrap(err)
		}
	}
	decision.apply(p.routingResult)
	return c.selectDialOption(p, decision.outbound, decision.mark, verified && c.dialTargetOverride)
}

// Route the selected target once, retaining immutable ingress identity.
// Outbound selection does not change the destination decision.
func (c *ControlPlane) routeDestination(p *RouteParam, domain string) (*DialOption, error) {
	input := p.routingInput(domain, p.effectiveDestination())
	input.afterTarget = true
	// A captured connection with no trusted hostname keeps its DNS-IP evidence.
	// Explicit IP URLs have a known logical target and do not borrow that identity.
	if domain == "" && !p.explicitTarget && c.core != nil && c.core.domainRegistry != nil {
		bump, routing := c.core.domainRegistry.kernelRoutingBitmaps(p.effectiveDestination().Addr())
		input.trustedDomainBitmap = [][]uint32{routing, bump}
	}
	outbound, mark, must, err := c.routingMatcher.match(input)
	if err != nil {
		return nil, err
	}
	if outbound >= consts.OutboundMustRules {
		return nil, fmt.Errorf("cannot resolve routing for %s without a trusted hostname", p.effectiveDestination())
	}
	routeDecision{outbound: outbound, mark: mark, must: must}.apply(p.routingResult)
	return c.selectDialOption(p, outbound, mark, c.dialTargetOverride && domain != "")
}

func (c *ControlPlane) Route(src, dst netip.AddrPort, domain string, l4proto consts.L4ProtoType, routingResult *bpfRoutingResult, trustedDomainBitmap ...[]uint32) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	input := routingResult.routingInput(src, dst, domain, l4proto)
	input.trustedDomainBitmap = trustedDomainBitmap
	return c.routingMatcher.match(input)
}

// A decision contains policy only. Selecting a node and creating a marked
// dialer happens after target transformation and policy evaluation complete.
type routeDecision struct {
	outbound consts.OutboundIndex
	mark     uint32
	must     bool
}

func (d routeDecision) apply(result *bpfRoutingResult) {
	result.Outbound, result.Mark, result.Must = uint8(d.outbound), d.mark, 0
	if d.must {
		result.Must = 1
	}
}

func kernelRoute(result *bpfRoutingResult) (routeDecision, bool) {
	d := routeDecision{outbound: consts.OutboundIndex(result.Outbound), mark: result.Mark, must: result.Must != 0}
	// Reserved outbound IDs are handoff instructions, never a usable decision.
	return d, d.outbound < consts.OutboundMustRules
}
