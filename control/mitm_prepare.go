// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// PreparedMITM pairs a protocol host with its expanded routing inputs. The plan
// is immutable and contains no external references requiring I/O at compilation.
type PreparedMITM struct {
	Host *mitm.Host
	plan plugin.Plan
}

// PrepareMITM consumes host, closing it on error. Refresh resources even when
// the host reuses every plugin instance: their declarations may refer to geodata.
func PrepareMITM(ctx context.Context, host *mitm.Host, dirs []string) (PreparedMITM, error) {
	if host == nil {
		return PreparedMITM{}, nil
	}
	plan := host.Plan()
	plan.DNS = nil // DNS middleware does not contribute kernel routing rules.
	var err error
	if len(plan.Destinations) != 0 {
		plan.Destinations, err = prepareDestinationRules(ctx, plan.Destinations, dirs)
	}
	reader := routing.NewDatReaderOptimizer(ctx, assets.NewLocationFinder(dirs))
	for _, rules := range []*[]*config_parser.RoutingRule{&plan.EarlyRoutes, &plan.Routes} {
		if err != nil {
			break
		}
		*rules, err = routing.ApplyRulesOptimizers(*rules, &routing.AliasOptimizer{}, reader, &routing.DeduplicateParamsOptimizer{})
	}
	if err != nil {
		return PreparedMITM{}, errors.Join(err, host.Close())
	}
	return PreparedMITM{Host: host, plan: plan}, nil
}

// prepareMITM loads plugins through the base routing policy, then rebuilds the
// userspace matcher with their declared routes and capture scopes. Shared BPF
// maps remain untouched until the control plane is activated.
func (c *ControlPlane) prepareMITM(ctx context.Context, conf *config.Config, rules *preparedRules, outbounds *outboundBuilder, load func(*http.Client) (PreparedMITM, error)) error {
	prepared, err := c.loadMITMHost(load)
	if err != nil {
		return err
	}
	c.mitmHost, c.mitmPlan = prepared.Host, prepared.plan
	if prepared.Host == nil {
		return nil
	}
	plan := prepared.plan
	rules.destinations = append(rules.destinations, plan.Destinations...)
	needsSniff := len(plan.Scopes) != 0
	for _, rule := range plan.Destinations {
		for _, f := range rule.Filter {
			needsSniff = needsSniff || f.Name == "domain"
		}
	}
	if needsSniff && c.sniffingTimeout <= 0 {
		c.sniffingTimeout = time.Second
	}
	rules.enableMITMPlan(plan)
	previousCount := len(c.outbounds)
	wasAsync := make([]bool, previousCount)
	for i, group := range c.outbounds {
		wasAsync[i] = group.CheckAsync
	}
	err = outbounds.buildRuleTargets(rules.earlyRoutes, rules.lateRoutes)
	if err == nil {
		err = outbounds.buildTargets(plan.RequiredOutbounds)
	}
	// Transfer partial construction too, so plane cleanup owns every transport.
	c.outbounds = outbounds.outbounds
	c.outboundReleases = outbounds.releases
	c.borrowedOutbounds = outbounds.borrowed
	if err != nil {
		return err
	}
	for _, group := range c.outbounds[previousCount:] {
		group.DeferStats()
	}
	c.connectivityOutbounds.Store(new(c.outbounds))
	builder, err := rules.compileRouting(outbounds.nameToID, c.core.bpf, c.core.ifmgr)
	if err != nil {
		return err
	}
	if c.routingMatcher, err = builder.BuildUserspace(); err != nil {
		return err
	}
	c.routingMatcher.outboundUsable = c.core.outboundUsable
	c.routingMatcherBuilder = builder
	c.routingState = builder.routingState
	c.criticalOutbounds = builder.criticalOutbounds(len(c.outbounds))
	for _, name := range plan.RequiredOutbounds {
		index, ok := outbounds.nameToID[name]
		if !ok {
			return fmt.Errorf("plugin requires unknown outbound %q", name)
		}
		c.criticalOutbounds[index] = true
	}
	configureOutboundChecks(c.outbounds, conf.Group, c.criticalOutbounds, outbounds.borrowed)
	if err := c.restoreRuntimeSettings(false); err != nil {
		return err
	}
	started := time.Now()
	waiters, err := startConnectivityChecks(c.outbounds[previousCount:])
	if err != nil {
		return err
	}
	for i, group := range c.outbounds[:previousCount] {
		// Existing synchronous groups already had their startup deadline. Only
		// newly critical groups need a barrier after the plugin phase.
		if !wasAsync[i] || group.CheckAsync {
			continue
		}
		ready, err := group.StartupReady()
		if err != nil {
			return fmt.Errorf("prepare outbound %q connectivity: %w", group.Name, err)
		}
		if ready != nil {
			waiters = append(waiters, startupConnectivityWaiter{name: group.Name, ready: ready})
		}
	}
	return waitForStartupConnectivity(waiters, max(initialConnectivityTimeout-time.Since(started), 0), ctx.Done())
}

func (c *ControlPlane) loadMITMHost(load func(*http.Client) (PreparedMITM, error)) (PreparedMITM, error) {
	client, closeDownloads := newMITMClient(c, 30*time.Second)
	defer closeDownloads()
	host, err := load(client)
	if err != nil {
		return PreparedMITM{}, fmt.Errorf("prepare plugins: %w", err)
	}
	return host, nil
}
