/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/status"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/mohae/deepcopy"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	// Network checks must be bounded on initial startup too: a disconnected
	// host can still start with configured nodes and persisted subscriptions.
	startupNetworkWaitTimeout       = 15 * time.Second
	reloadNetworkWaitTimeout        = 15 * time.Second
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

func waitForNetworkOnline(ctx context.Context, isReload bool) error {
	timeout := startupNetworkWaitTimeout
	if isReload {
		timeout = reloadNetworkWaitTimeout
		writeReloadProgress("Checking network...")
	}
	return waitForNetworkOnlineWithTimeout(ctx, timeout)
}

func waitForNetworkOnlineWithTimeout(ctx context.Context, timeout time.Duration) error {
	const retryInterval = 5 * time.Second
	if len(CheckNetworkLinks) == 0 {
		return errors.New("network check has no endpoints")
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return direct.Direct.DialContext(ctx, "tcp", addr)
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

func newControlPlane(ctx context.Context, datapath *control.Runtime, conf *config.Config, externGeoDataDirs []string, runtimeSettings *settings.Store, plugins *mitm.Configuration) (c *control.ControlPlane, err error) {
	if datapath == nil {
		datapath = control.NewRuntime()
	}
	isReload := datapath.IsReload()
	defer func() {
		if err == nil || isReload {
			return
		}
		err = errors.Join(err, datapath.Close(), cleanupStartup(nil))
	}()
	conf = deepcopy.Copy(conf).(*config.Config)
	var autoSelected bool
	conf.Global.SoMarkFromDae, autoSelected = common.ResolveSoMarkFromDae(conf.Global.SoMarkFromDae, conf.Global.SoMarkFromDaeSet)
	if err = common.ValidateSoMarkFromDae(conf.Global.SoMarkFromDae); err != nil {
		return nil, err
	}
	if autoSelected {
		log.WithField("so_mark_from_dae", "0x100").Debug("Using default internal socket mark")
	}
	direct.InitDirectDialers(conf.Global.Mptcp, int(conf.Global.SoMarkFromDae))

	var nodeDescriptors []outbound.NodeDescriptor
	var preparation *control.ControlPlanePreparation
	defer func() {
		if err == nil {
			return
		}
		if closeErr := preparation.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close control plane preparation: %w", closeErr))
		}
	}()
	log.Debug("Preparing nodes, routing rules, and eBPF resources")
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		var prepareErr error
		preparation, prepareErr = control.PrepareControlPlane(groupCtx, datapath, &conf.Routing, &conf.Global, externGeoDataDirs, conf.Rules)
		return prepareErr
	})
	group.Go(func() error {
		var resolveErr error
		nodeDescriptors, resolveErr = resolveNodeDescriptors(groupCtx, conf, isReload, filepath.Dir(cfgFile), subscription.ResolveSubscriptionContext)
		return resolveErr
	})
	if err = group.Wait(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	var mitmLoader func(*http.Client, *http.Client) (*mitm.Host, error)
	if len(conf.Plugins) != 0 {
		mitmLoader = func(client, background *http.Client) (*mitm.Host, error) {
			if isReload {
				writeReloadProgress("Preparing plugins using routing rules...")
			}
			return loadMITM(ctx, conf, client, background, plugins)
		}
	}
	assemblyStarted := time.Now()
	c, err = control.NewControlPlane(ctx, preparation, nodeDescriptors, conf,
		runtimeSettings, mitmLoader)
	if err != nil {
		return nil, err
	}
	if contextErr := ctx.Err(); contextErr != nil {
		err = errors.Join(contextErr, c.Close())
		c = nil
		return nil, err
	}
	runtime.GC()
	c.SetDomainRegistryPath(filepath.Join(cacheDirectory(), "domain-registry.json.gz"))
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

func cleanupStartup(c *control.ControlPlane) error {
	var err error
	if c != nil {
		err = errors.Join(c.Runtime().Close(), c.Close())
	}
	if netns := control.GetDaeNetns(); netns != nil {
		err = errors.Join(err, netns.Close())
	}
	control.CloseSysctlManager()
	return err
}

func resolveNodeDescriptors(
	ctx context.Context,
	conf *config.Config,
	isReload bool,
	configDir string,
	resolve subscriptionResolver,
) ([]outbound.NodeDescriptor, error) {
	started := time.Now()
	descriptors := make([]outbound.NodeDescriptor, 0, len(conf.Node))
	for _, node := range conf.Node {
		descriptors = append(descriptors, outbound.NodeDescriptor{
			Name: node.Name, Link: node.Link, Options: node.Options, Required: true,
		})
	}
	if !conf.Global.DisableWaitingNetwork {
		if err := waitForNetworkOnline(ctx, isReload); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cache := resource.Cache{}
	if conf.Global.ResourceCache {
		cache.Dir = filepath.Join(cacheDirectory(), "resources", "subscriptions")
	}
	var cacheKeys []string
	for _, sub := range conf.Subscription {
		_, raw := resource.Split(sub.String())
		if source, err := resource.Parse(raw, configDir); err == nil && source.Remote() {
			cacheKeys = append(cacheKeys, source.Location)
		}
	}
	if len(conf.Subscription) > 0 {
		if isReload {
			writeReloadProgress("Fetching subscriptions...")
		}
		log.WithField("subscriptions", len(conf.Subscription)).Debug("Fetching subscriptions")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return direct.Direct.DialContext(ctx, "tcp", addr)
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
			results[i].tag, results[i].nodes, results[i].err = resolve(loadCtx, &client, options, link, validateNode)
			return nil
		})
	}
	resolveGroup.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if errors.Is(loadCtx.Err(), context.DeadlineExceeded) {
		log.Warn("Subscription loading budget exhausted; skipping unfinished subscriptions")
	}

	for i, result := range results {
		sub := conf.Subscription[i]
		if result.err != nil {
			log.WithError(resource.RedactError(result.err)).WithField("subscription", subscription.RedactURL(sub.String())).Warn("Subscription unavailable; skipping its nodes")
			continue
		}
		for _, link := range result.nodes {
			descriptors = append(descriptors, outbound.NodeDescriptor{
				Link: link, SubscriptionTag: result.tag,
				Defaults: sub.Option.Defaults, Rules: sub.Option.Rules,
			})
		}
	}
	if err := cache.Prune(cacheKeys); err != nil {
		log.WithError(err).Warn("Could not prune subscription resource cache")
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

func readConfig(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}
