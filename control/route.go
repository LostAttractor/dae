// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"hash/maphash"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
)

type RouteParam struct {
	destinationSeed  *maphash.Seed         // UDP source lifetime; nil selects a fresh target for this attempt.
	outboundOverride *consts.OutboundIndex // Explicit auxiliary HTTP policy; retains destination, mark and identity.
	explicitTarget   bool                  // An explicit URL supplies a known name, or a literal IP with no name.
	destination      netip.AddrPort        // Selected IP target; invalid until a rewrite or retained UDP target exists.
	routingResult    *routingResult
	networkType      common.NetworkType
	Domain           string
	Src              netip.AddrPort
	Dest             netip.AddrPort // Input target of this attempt; destination matching never mutates it.
}

func (c *ControlPlane) RouteDialOption(ctx context.Context, p *RouteParam) (*DialOption, error) {
	return c.routeDialOption(ctx, p, nil)
}

// useDNSAddress is borrowed for this selection, never retained in the option.
// Nil selects the currently published host's policy.
func (c *ControlPlane) routeDialOption(ctx context.Context, p *RouteParam, useDNSAddress func(string) bool) (*DialOption, error) {
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
	decision, _ := kernelRoute(p.routingResult)
	facts := routeFacts{
		outbound: decision.outbound, capture: p.routingResult.CaptureFlags,
		destination: p.destination.IsValid(), mode: c.rerouteMode,
		verified: predicateUnknown, dialOverride: c.dialTargetOverride,
	}
	if planRoute(facts).preserve {
		decision.apply(p.routingResult)
		return c.selectDialOption(ctx, p, decision.outbound, decision.mark, false, useDNSAddress)
	}
	verified, err := c.verifySniff(ctx, p.Dest, p.Domain)
	if err != nil {
		return nil, err
	}
	domain := p.Domain
	if !verified {
		domain = ""
	}
	facts.verified = routingTruth(verified)
	plan := planRoute(facts)
	switch plan.action {
	case routeTarget:
		return c.routeDestination(ctx, p, domain, useDNSAddress)
	case routeMatch:
		// Without a trusted hostname this resolves a kernel handoff with the
		// kernel's own DNS evidence. Ambiguity it could not resolve remains.
		input := p.routingInput(domain, p.Dest)
		if domain == "" {
			input.domainBumpBitmap, input.domainBitmap = c.kernelDomainEvidence(p.Dest.Addr())
		}
		decision.outbound, decision.mark, decision.must, err = c.routingMatcher.match(input)
		if err != nil {
			return nil, err
		}
		if decision.outbound > consts.OutboundUserDefinedMax {
			return nil, fmt.Errorf("cannot resolve routing for %s without a trusted hostname", p.Dest.Addr())
		}
	}

	decision.apply(p.routingResult)
	return c.selectDialOption(ctx, p, decision.outbound, decision.mark, plan.override, useDNSAddress)
}

// Route the selected target once, retaining immutable ingress identity.
// Outbound selection does not change the destination decision.
func (c *ControlPlane) routeDestination(ctx context.Context, p *RouteParam, domain string, useDNSAddress func(string) bool) (*DialOption, error) {
	input := p.routingInput(domain, p.effectiveDestination())
	// A captured connection with no trusted hostname keeps its DNS-IP evidence.
	// Explicit IP URLs have a known logical target and do not borrow that identity.
	var bump, routing []uint32
	if domain == "" && !p.explicitTarget {
		bump, routing = c.kernelDomainEvidence(input.dst.Addr())
	}
	input = input.targetInput(domain, p.explicitTarget, bump, routing)
	outbound, mark, must, err := c.routingMatcher.match(input)
	if err != nil {
		return nil, err
	}
	if outbound > consts.OutboundUserDefinedMax {
		return nil, fmt.Errorf("cannot resolve routing for %s without a trusted hostname", input.dst)
	}
	if p.outboundOverride != nil {
		outbound = *p.outboundOverride
	}
	routeDecision{outbound: outbound, mark: mark, must: must}.apply(p.routingResult)
	return c.selectDialOption(ctx, p, outbound, mark, c.dialTargetOverride && domain != "", useDNSAddress)
}

// kernelDomainEvidence returns the domain bitmaps the kernel routes the address
// with: the AND and OR of every domain the address is mapped to.
func (c *ControlPlane) kernelDomainEvidence(addr netip.Addr) (bump, routing []uint32) {
	if c.core == nil || c.core.domainRegistry == nil {
		return nil, nil
	}
	return c.core.domainRegistry.kernelRoutingBitmaps(addr)
}

// A decision contains policy only. Selecting a node and creating a marked
// dialer happens after target transformation and policy evaluation complete.
type routeDecision struct {
	outbound consts.OutboundIndex
	mark     uint32
	must     bool
}

func (d routeDecision) apply(result *routingResult) {
	result.Outbound, result.Mark, result.Must = uint8(d.outbound), d.mark, 0
	if d.must {
		result.Must = 1
	}
}

func kernelRoute(result *routingResult) (routeDecision, bool) {
	d := routeDecision{outbound: consts.OutboundIndex(result.Outbound), mark: result.Mark, must: result.Must != 0}
	// Reserved outbound IDs are handoff instructions, never a usable decision.
	return d, d.outbound <= consts.OutboundUserDefinedMax
}

// verifySniff reports whether domain is the domain of dst.
// SniffVerifyMode_Loose passes when the domain is known.
// SniffVerifyMode_Strict passes when a matching DNS resolution was observed.
func (c *ControlPlane) verifySniff(ctx context.Context, dst netip.AddrPort, domain string) (verified bool, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	if domain == "" {
		return
	}
	fqdn := dnsmessage.CanonicalName(domain)
	// Pairing remains valid until time GC, even if the corresponding kernel
	// state is capacity-evicted.
	verification := c.core.domainRegistry.Verify(fqdn, dst.Addr())
	if verification.Registered {
		switch c.sniffVerifyMode {
		case consts.SniffVerifyMode_None, consts.SniffVerifyMode_Loose:
			verified = true
		case consts.SniffVerifyMode_Strict:
			verified = verification.Paired
		}
	} else {
		// Successful sniff without DNS lookup record.
		// Check if the domain is in real-domain set (bloom filter).
		switch c.sniffVerifyMode {
		case consts.SniffVerifyMode_None:
			verified = true
		case consts.SniffVerifyMode_Strict:
			verified = false
		case consts.SniffVerifyMode_Loose:
			c.muRealDomainSet.Lock()
			verified = c.realDomainSet.TestString(fqdn)
			c.muRealDomainSet.Unlock()
			if !verified {
				// Check existence through the system resolver; this is not observed client DNS evidence.
				ip46, resolveErr := netutils.ResolveIp46Context(ctx, fqdn)
				if resolveErr != nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						err = ctxErr
					}
					return
				}
				if ip46.IsValid() {
					// Add it to real-domain set.
					c.muRealDomainSet.Lock()
					c.realDomainSet.AddString(fqdn)
					c.muRealDomainSet.Unlock()
					verified = true
				}
			}
		}
	}
	return
}
