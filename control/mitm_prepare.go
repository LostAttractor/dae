// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/config"
)

// prepareMITM loads plugins through the base routing policy, then rebuilds the
// userspace matcher with their declared routes and capture scopes. Shared BPF
// maps remain untouched until the control plane is activated.
func (c *ControlPlane) prepareMITM(ctx context.Context, conf *config.Config, rules *preparedRules, outboundName2Id map[string]uint8, load func(*http.Client, *http.Client) (*mitm.Host, error)) error {
	host, err := c.loadMITMHost(load)
	if err != nil {
		return err
	}
	c.mitmHost = host
	if host == nil {
		return nil
	}
	plan := host.Plan()
	pluginDestinations, err := prepareDestinationRules(ctx, plan.Destinations, rules.geoDirs)
	if err != nil {
		return err
	}
	rules.destinations = append(rules.destinations, pluginDestinations...)
	needsSniff := len(plan.Scopes) != 0
	for _, rule := range pluginDestinations {
		for _, f := range rule.Filter {
			needsSniff = needsSniff || f.Name == "domain"
		}
	}
	if needsSniff && c.sniffingTimeout <= 0 {
		c.sniffingTimeout = time.Second
	}
	rules.enableMITMPlan(plan)
	if err := rules.bypassLocalAPI(conf.Global.APIPort); err != nil {
		return err
	}
	builder, err := rules.compileRouting(outboundName2Id, c.core.bpf, c.core.ifmgr)
	if err != nil {
		return err
	}
	if c.routingMatcher, err = builder.BuildUserspace(); err != nil {
		return err
	}
	c.routingMatcher.outboundUsable = c.core.outboundUsable
	c.routingMatcherBuilder = builder
	if err := c.restoreClientSets(); err != nil {
		return err
	}
	c.criticalOutbounds = builder.criticalOutbounds(len(c.outbounds))
	return nil
}

func (c *ControlPlane) loadMITMHost(load func(*http.Client, *http.Client) (*mitm.Host, error)) (*mitm.Host, error) {
	client, closeDownloads := newMITMClient(c, 30*time.Second)
	defer closeDownloads()
	background, closeBackground := newMITMClient(c, 0)
	// Background requests belong to the plane, not this preparation call.
	// Close them before DNS relays and outbounds during plane cleanup.
	c.deferFuncs = append(c.deferFuncs, func() error { closeBackground(); return nil })
	host, err := load(client, background)
	if err != nil {
		return nil, fmt.Errorf("prepare plugins: %w", err)
	}
	return host, nil
}
