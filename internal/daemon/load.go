/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package daemon

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/status"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	// Network checks must be bounded on initial startup too: a disconnected
	// host can still start with configured nodes and persisted subscriptions.
	startupNetworkWaitTimeout       = 15 * time.Second
	reloadSubscriptionTimeout       = 10 * time.Second
	reloadSubscriptionPhaseTimeout  = 30 * time.Second
	startupSubscriptionPhaseTimeout = 2 * time.Minute
	subscriptionFallbackTimeout     = 5 * time.Second
	maxConcurrentSubscriptions      = 4
)

var CheckNetworkLinks = []string{
	"http://edge.microsoft.com/captiveportal/generate_204",
	"http://www.gstatic.com/generate_204",
	"http://www.qualcomm.cn/generate_204",
}

func init() {
	rand.Shuffle(len(CheckNetworkLinks), func(i, j int) {
		CheckNetworkLinks[i], CheckNetworkLinks[j] = CheckNetworkLinks[j], CheckNetworkLinks[i]
	})
}

type subscriptionResolution struct {
	tag   string
	nodes []string
	err   error
}

type subscriptionResolver func(context.Context, *http.Client, subscription.ResolveOptions, string, func(string) error) (string, []string, error)

func waitForNetworkOnline(ctx context.Context, timeout time.Duration, dialer netproxy.Dialer) error {
	const retryInterval = 5 * time.Second
	if len(CheckNetworkLinks) == 0 {
		return errors.New("network check has no endpoints")
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: retryInterval}
	waitRetry := func() {
		timer := time.NewTimer(retryInterval)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-waitCtx.Done():
		}
	}
	log.Debug("Checking startup network reachability")
	for i := 0; ; i++ {
		if contextErr := waitCtx.Err(); contextErr != nil {
			if errors.Is(contextErr, context.DeadlineExceeded) && ctx.Err() == nil {
				log.WithField("timeout", timeout).Warn("Startup network check timed out; continuing with configured nodes and subscriptions")
				return nil
			}
			return contextErr
		}
		req, err := http.NewRequestWithContext(waitCtx, http.MethodGet, CheckNetworkLinks[i%len(CheckNetworkLinks)], nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			if waitCtx.Err() != nil {
				continue
			}
			log.WithError(resource.RedactError(err)).WithField("endpoint", resource.RedactURL(req.URL.String())).Debug("Startup network check failed")
			if neterr, ok := errors.AsType[net.Error](err); ok && neterr.Timeout() {
				continue
			}
			waitRetry()
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			log.Debug("Startup network check passed")
			return nil
		}
		log.WithFields(log.Fields{"endpoint": resource.RedactURL(req.URL.String()), "status": resp.StatusCode}).Debug("Startup network check returned an unexpected HTTP status")
		waitRetry()
	}
}

type controlInputs struct {
	nodes  []outbound.NodeDescriptor
	rules  *control.PreparedRules
	global config.Global
}

func loadControlInputs(ctx context.Context, conf *config.Config, isReload bool, dirs []string, configFile string, previous *controlInputs) (*controlInputs, error) {
	input := &controlInputs{global: conf.Global}
	preparation := nodePreparation{}
	if previous != nil && reflect.DeepEqual(dialer.NewGlobalOption(&previous.global), dialer.NewGlobalOption(&conf.Global)) {
		preparation.known = previous.nodes
	}
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		var err error
		input.rules, err = control.PrepareRules(groupCtx, &conf.Routing, conf.Rules, dirs)
		return err
	})
	group.Go(func() error {
		var err error
		input.nodes, err = resolveNodeDescriptors(groupCtx, conf, isReload, filepath.Dir(configFile), subscription.ResolveSubscriptionContext, preparation)
		return err
	})
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return input, ctx.Err()
}

func (input *controlInputs) equal(other *controlInputs) bool {
	return input != nil && other != nil && reflect.DeepEqual(input.nodes, other.nodes) && input.rules.Equal(other.rules)
}

// management-independent inputs are compared after expanding external resources.
func sameControlConfig(previous, next *config.Config) bool {
	project := func(conf *config.Config) config.Config {
		value := *conf
		value.Plugins, value.Subscription, value.Node = nil, nil, nil
		value.Routing, value.Rules = config.Routing{}, config.Rules{}
		value.MITM.CACert, value.MITM.CAKey = "", ""
		value.MITM.BufferMemoryLimit = 0
		value.Global.LogLevel, value.Global.APIKey = "", ""
		value.Global.PprofPort, value.Global.MetricsPort = 0, 0
		value.Global.ResourceCache, value.Global.DisableWaitingNetwork = false, false
		value.Global.ResourceUpdateInterval = 0
		value.Global.SoMarkFromDae = common.EffectiveSoMarkFromDae(value.Global.SoMarkFromDae)
		value.Global.SoMarkFromDaeSet = false
		return value
	}
	return reflect.DeepEqual(project(previous), project(next))
}

func newControlPlane(ctx context.Context, datapath *control.Runtime, conf *config.Config, inputs *controlInputs, runtimeSettings *settings.Store, loadMITM func(*http.Client) (control.PreparedMITM, error)) (*control.ControlPlane, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mark, autoSelected := common.ResolveSoMarkFromDae(conf.Global.SoMarkFromDae, conf.Global.SoMarkFromDaeSet)
	if err := common.ValidateSoMarkFromDae(mark); err != nil {
		return nil, err
	}
	if autoSelected {
		log.WithField("so_mark_from_dae", "0x100").Debug("Using default internal socket mark")
	}
	preparation, err := control.PrepareControlPlane(ctx, datapath, mark, inputs.rules)
	if err != nil {
		return nil, err
	}
	defer preparation.Close()

	assemblyStarted := time.Now()
	c, err := control.NewControlPlane(ctx, preparation, inputs.nodes, conf, runtimeSettings, loadMITM)
	if err != nil {
		return nil, err
	}
	c.SetDomainRegistryPath(filepath.Join(common.CacheDirectory(), "domain-registry.json.gz"))
	if err := c.PrepareKernel(); err != nil {
		return nil, errors.Join(err, c.Close())
	}
	log.WithField("duration", time.Since(assemblyStarted)).Debug("Assembled control plane")
	logStartupMITMStatus(c.MITMStatus())
	return c, nil
}

func logStartupNodeStatus(groups []api.GroupStatus) {
	if !log.IsLevelEnabled(log.DebugLevel) {
		return
	}
	output := status.RenderStartupNodes(groups)
	if output == "" {
		return
	}
	for line := range strings.SplitSeq(output, "\n") {
		log.Debug(line)
	}
}

func cleanupKernelResources() error {
	var err error
	if netns := control.GetDaeNetns(); netns != nil {
		err = netns.Close()
	}
	control.CloseSysctlManager()
	return err
}

type nodePreparation struct {
	dialer netproxy.Dialer
	known  []outbound.NodeDescriptor
}

func resolveNodeDescriptors(
	ctx context.Context,
	conf *config.Config,
	isReload bool,
	configDir string,
	resolve subscriptionResolver,
	preparation nodePreparation,
) ([]outbound.NodeDescriptor, error) {
	started := time.Now()
	dialer, err := bootstrapDialer(conf.Global)
	if err != nil {
		return nil, err
	}
	if preparation.dialer != nil {
		dialer = preparation.dialer
	}
	descriptors := make([]outbound.NodeDescriptor, 0, len(conf.Node))
	for _, node := range conf.Node {
		descriptors = append(descriptors, outbound.NodeDescriptor{
			Name: node.Name, Link: node.Link, Options: node.Options, Required: true,
		})
	}
	if !isReload && !conf.Global.DisableWaitingNetwork {
		if err := waitForNetworkOnline(ctx, startupNetworkWaitTimeout, dialer); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cache := resource.Cache{}
	if conf.Global.ResourceCache {
		cache.Dir = filepath.Join(common.CacheDirectory(), "resources", "subscriptions")
	}
	if len(conf.Subscription) > 0 {
		log.WithField("subscriptions", len(conf.Subscription)).Debug("Fetching subscriptions")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 30 * time.Second}
	phaseTimeout := startupSubscriptionPhaseTimeout
	if isReload {
		client.Timeout = reloadSubscriptionTimeout
		phaseTimeout = reloadSubscriptionPhaseTimeout
	}
	refreshDeadline := time.Now().Add(phaseTimeout)
	// Keep parsing/dialer validation bounded too, with a small separate budget
	// for cached resources after the network refresh budget is exhausted.
	loadDeadline := refreshDeadline
	if cache.Dir != "" {
		loadDeadline = loadDeadline.Add(subscriptionFallbackTimeout)
	}
	loadCtx, cancel := context.WithDeadline(ctx, loadDeadline)
	defer cancel()
	validateNode := outbound.NewNodeValidator(loadCtx, &conf.Global)
	known := make(map[string]bool, len(preparation.known))
	for _, node := range preparation.known {
		if !node.Required {
			known[node.Link] = true
		}
	}
	validate := func(link string) error {
		if known[link] {
			return loadCtx.Err()
		}
		return validateNode(link)
	}
	results := make([]subscriptionResolution, len(conf.Subscription))
	var resolveGroup errgroup.Group
	resolveGroup.SetLimit(maxConcurrentSubscriptions)
	for i, sub := range conf.Subscription {
		if loadCtx.Err() != nil {
			break
		}
		resolveGroup.Go(func() error {
			link := sub.String()
			options := subscription.ResolveOptions{BaseDir: configDir, CacheDir: cache.Dir, RefreshDeadline: refreshDeadline}
			results[i].tag, results[i].nodes, results[i].err = resolve(loadCtx, &client, options, link, validate)
			return nil
		})
	}
	resolveGroup.Wait()
	if isReload && loadCtx.Err() != nil {
		return nil, loadCtx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if errors.Is(loadCtx.Err(), context.DeadlineExceeded) {
		log.Warn("Subscription loading budget exhausted; skipping unfinished subscriptions")
	}

	for i, result := range results {
		sub := conf.Subscription[i]
		if result.err != nil {
			if isReload {
				return nil, fmt.Errorf("subscription %s: %w", subscription.RedactURL(sub.String()), result.err)
			}
			log.WithError(resource.RedactError(result.err)).WithField("subscription", subscription.RedactURL(sub.String())).Warn("Subscription unavailable; skipping its nodes")
			continue
		}
		for _, link := range result.nodes {
			descriptors = append(descriptors, outbound.NodeDescriptor{
				Link: link, SubscriptionTag: result.tag, SelectionSource: selector.SubscriptionSource(result.tag, sub.Link),
				Defaults: sub.Option.Defaults, Rules: sub.Option.Rules,
			})
		}
	}
	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Debug("No interfaces configured for traffic interception")
	}
	log.WithFields(log.Fields{
		"duration": time.Since(started),
		"nodes":    len(descriptors),
	}).Debug("Prepared nodes")
	return descriptors, nil
}

func pruneSubscriptions(conf *config.Config, configDir string) {
	if !conf.Global.ResourceCache {
		return
	}
	cache := resource.Cache{Dir: filepath.Join(common.CacheDirectory(), "resources", "subscriptions")}
	var keys []string
	for _, sub := range conf.Subscription {
		_, raw := resource.Split(sub.String())
		if source, err := resource.Parse(raw, configDir); err == nil && source.Remote() {
			keys = append(keys, source.Location)
		}
	}
	if err := cache.Prune(keys); err != nil {
		log.WithError(err).Warn("Could not prune subscription resource cache")
	}
}

func bootstrapDialer(global config.Global) (netproxy.Dialer, error) {
	option := direct.Option{Mptcp: global.Mptcp, Mark: int(common.EffectiveSoMarkFromDae(global.SoMarkFromDae)), Resolver: &net.Resolver{PreferGo: true}}
	physical := direct.NewDirectDialer(option)
	resolver, err := netutils.NewBootstrapResolver(global.DNSResolver, physical.DialContext)
	if err != nil {
		return nil, err
	}
	option.Resolver = resolver
	return direct.NewDirectDialer(option), nil
}
