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

// PreparedMITM holds immutable routing inputs and an optional host constructor.
// BuildHost may retain prepared values, but must own no live resources before it
// is called. Host is set only after construction, or by PrepareMITM for reuse.
type PreparedMITM struct {
	Host      *mitm.Host
	BuildHost func(context.Context) (*mitm.Host, error)
	plan      plugin.Plan
}

func (p *PreparedMITM) Build(ctx context.Context) error {
	if p.BuildHost == nil {
		return nil
	}
	if p.Host != nil {
		return errors.New("prepared plugins already have a host")
	}
	host, err := p.BuildHost(ctx)
	if err != nil {
		return err
	}
	p.Host, p.BuildHost = host, nil
	return nil
}

// BuildServices constructs live instances only after the final routing inputs
// have been accepted. Input-only preparation never calls this method.
func (c *ControlPlane) BuildServices(ctx context.Context) error {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	if c.core.closed.Err() != nil {
		return c.core.closed.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.pendingMITM == nil {
		return nil
	}
	if err := c.pendingMITM.Build(ctx); err != nil {
		return err
	}
	c.mitmHost, c.pendingMITM = c.pendingMITM.Host, nil
	return nil
}

// PrepareMITM consumes host, closing it on error. Refresh resources even when
// the host reuses every plugin instance: their declarations may refer to geodata.
func PrepareMITM(ctx context.Context, host *mitm.Host, dirs []string) (PreparedMITM, error) {
	if host == nil {
		return PreparedMITM{}, nil
	}
	prepared, err := PrepareMITMPlan(ctx, host.Plan(), dirs)
	if err != nil {
		return PreparedMITM{}, errors.Join(err, host.Close())
	}
	prepared.Host = host
	return prepared, nil
}

// PrepareMITMPlan expands static declarations without constructing a host or VM.
func PrepareMITMPlan(ctx context.Context, plan plugin.Plan, dirs []string) (PreparedMITM, error) {
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
		return PreparedMITM{}, err
	}
	return PreparedMITM{plan: plan}, nil
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
	c.pendingMITM = &prepared
	plan := prepared.plan
	rules.destinations = append(rules.destinations, plan.Destinations...)
	rules.enableMITMPlan(plan)
	previousCount := len(c.outbounds)
	wasAsync := c.outboundCheckAsync
	err = outbounds.buildRuleTargets(rules.earlyRoutes, rules.lateRoutes)
	if err == nil {
		err = outbounds.buildTargets(plan.RequiredOutbounds)
	}
	// Transfer partial construction too, so plane cleanup owns every transport.
	c.adoptOutbounds(outbounds)
	if err != nil {
		return err
	}
	for _, group := range c.outbounds[previousCount:] {
		group.DeferStats()
	}
	c.connectivityOutbounds.Store(new(c.outbounds))
	if err := c.installRouting(rules, outbounds.nameToID, conf.Group, plan.RequiredOutbounds); err != nil {
		return err
	}
	if err := c.restoreRuntimeSettings(false); err != nil {
		return err
	}
	started := time.Now()
	waiters, err := startConnectivityChecks(c.outbounds[previousCount:], c.outboundCheckAsync[previousCount:])
	if err != nil {
		return err
	}
	if c.skipConnectivityWait {
		return nil
	}
	for i, group := range c.outbounds[:previousCount] {
		// Existing synchronous groups already had their startup deadline. Only
		// newly critical groups need a barrier after the plugin phase.
		if !wasAsync[i] || c.outboundCheckAsync[i] {
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
