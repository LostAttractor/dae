// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

// installRouting prepares one userspace routing program, both before plugin
// loading and after its declarations have been added. Kernel writes remain
// deferred to activation; connectivity barriers belong to the startup phase.
func (c *ControlPlane) installRouting(rules *preparedRules, outbounds map[string]uint8, groups []config.Group, required []string) error {
	builder, err := rules.compileRouting(outbounds, c.core.bpf, c.core.ifmgr)
	if err != nil {
		return fmt.Errorf("compile routing: %w", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		return fmt.Errorf("build userspace routing: %w", err)
	}
	critical := builder.criticalOutbounds(len(c.outbounds))
	for _, name := range required {
		index, ok := outbounds[name]
		if !ok {
			return fmt.Errorf("plugin requires unknown outbound %q", name)
		}
		critical[index] = true
	}
	matcher.outboundUsable = c.core.outboundUsable
	c.routingMatcher, c.routingState = matcher, matcher.routingState
	c.criticalOutbounds = critical
	c.outboundCheckAsync = configureOutboundChecks(c.outbounds, groups, critical)
	if c.sniffingTimeout <= 0 && builder.requiresSniffing() {
		c.sniffingTimeout = time.Second
	}
	return nil
}

// Derive forced sniffing from the installed program, including plugin HTTP
// capture and domain-dependent DNAT. Ordinary domain routing may use DNS alone.
func (b *RoutingMatcherBuilder) requiresSniffing() bool {
	for _, profile := range b.profiles {
		for _, predicate := range profile.Destination.predicates {
			if predicate.domain {
				return true
			}
		}
		for _, span := range profile.Spans {
			for _, rule := range b.rules[span.Start:span.End] {
				if rule.Action == uint8(consts.MatchActionCapture) && rule.Flags&(captureHTTP<<matchCaptureShift) != 0 {
					return true
				}
			}
		}
	}
	return false
}
