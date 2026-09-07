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
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/mohae/deepcopy"
	"github.com/samber/oops"
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

type subscriptionResolver func(context.Context, *http.Client, string, string, func(string) error) (string, []string, error)

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
	log.Infoln("Waiting for network...")
	for i := 0; ; i++ {
		if contextErr := waitCtx.Err(); contextErr != nil {
			if errors.Is(contextErr, context.DeadlineExceeded) && ctx.Err() == nil {
				log.Warnf("Network is still not online after %v; continuing with configured nodes and subscription resolution", timeout)
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
			log.Debugf("%+v", oops.Wrapf(err, "CheckNetwork"))
			var neterr net.Error
			if errors.As(err, &neterr) && neterr.Timeout() {
				continue
			}
			waitRetry()
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			log.Infoln("Network online.")
			return nil
		}
		log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
		waitRetry()
	}
}

func newControlPlane(ctx context.Context, bpf any, conf *config.Config, externGeoDataDirs []string, runtimeSettings *settings.Store, setups map[string]plugin.Setup) (c *control.ControlPlane, err error) {
	defer func() {
		if err == nil || bpf != nil {
			return
		}
		err = errors.Join(err, cleanupStartup(nil))
	}()
	conf = deepcopy.Copy(conf).(*config.Config)
	var autoSelected bool
	conf.Global.SoMarkFromDae, autoSelected = common.ResolveSoMarkFromDae(conf.Global.SoMarkFromDae, conf.Global.SoMarkFromDaeSet)
	if err = common.ValidateSoMarkFromDae(conf.Global.SoMarkFromDae); err != nil {
		return nil, err
	}
	if autoSelected {
		log.Warn("so_mark_from_dae is unset; using reserved internal socket mark 0x100 for policy routing")
	}
	activeSubscriptionTags, err := persistentSubscriptionTags(conf.Subscription)
	if err != nil {
		return nil, err
	}
	direct.InitDirectDialers(conf.Global.FallbackResolver, conf.Global.Mptcp, int(conf.Global.SoMarkFromDae))

	var nodeDescriptors []outbound.NodeDescriptor
	var preparation *control.ControlPlanePreparation
	defer func() {
		if err == nil {
			return
		}
		if closeErr := preparation.Close(); closeErr != nil {
			err = errors.Join(err, oops.Wrapf(closeErr, "close control plane preparation"))
		}
	}()
	log.Info("Preparing nodes, routing rules, and eBPF resources in parallel")
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		var prepareErr error
		preparation, prepareErr = control.PrepareControlPlane(groupCtx, bpf, &conf.Routing, &conf.Global, &conf.Dns, externGeoDataDirs, conf.Rules)
		return prepareErr
	})
	group.Go(func() error {
		var resolveErr error
		nodeDescriptors, resolveErr = resolveNodeDescriptors(groupCtx, conf, activeSubscriptionTags, bpf != nil, filepath.Dir(cfgFile), subscription.ResolveSubscriptionContext)
		return resolveErr
	})
	if err = group.Wait(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	var mitmLoader func(*http.Client, *http.Client) (*mitm.Host, error)
	if conf.MITM.Enabled {
		mitmLoader = func(client, background *http.Client) (*mitm.Host, error) {
			if bpf != nil {
				writeReloadProgress("Preparing MITM plugins using routing rules...")
			}
			return loadMITM(ctx, conf, client, background, setups)
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
	log.WithField("duration", time.Since(assemblyStarted)).Info("Assembled control plane")
	logStartupMITMStatus(c.MITMStatus())
	return c, nil
}

func cleanupStartup(c *control.ControlPlane) error {
	var err error
	if c != nil {
		err = c.Close()
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
	activeTags map[string]struct{},
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

	subscriptionDir := cacheDirectory()
	if len(conf.Subscription) > 0 {
		if isReload {
			writeReloadProgress("Fetching subscriptions...")
		}
		log.Infoln("Fetching subscriptions...")
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
	subCtx, cancel := context.WithTimeout(ctx, phaseTimeout)
	defer cancel()
	validateNode := outbound.NewNodeValidator(subCtx, &conf.Global)
	results := make([]subscriptionResolution, len(conf.Subscription))
	var resolveGroup errgroup.Group
	resolveGroup.SetLimit(maxConcurrentSubscriptions)
	for i, sub := range conf.Subscription {
		if subCtx.Err() != nil {
			break
		}
		resolveGroup.Go(func() error {
			link := sub.String()
			dir := subscriptionSourceDirectory(link, configDir)
			results[i].tag, results[i].nodes, results[i].err = resolve(subCtx, &client, dir, link, validateNode)
			return nil
		})
	}
	resolveGroup.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if errors.Is(subCtx.Err(), context.DeadlineExceeded) {
		log.Warnf("Subscription resolution exceeded %v; skipping unfinished subscriptions", phaseTimeout)
	}

	resolvingFailed := false
	for i, result := range results {
		sub := conf.Subscription[i]
		if result.err != nil {
			resolvingFailed = true
			phaseCanceled := subCtx.Err() != nil && (errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded))
			if !phaseCanceled {
				log.Warnf("failed to resolve subscription %q: %v", subscription.RedactURL(sub.String()), result.err)
			}
			continue
		}
		for _, link := range result.nodes {
			descriptors = append(descriptors, outbound.NodeDescriptor{
				Link: link, SubscriptionTag: result.tag,
				Defaults: sub.Option.Defaults, Rules: sub.Option.Rules,
			})
		}
	}
	if err := subscription.PrunePersistedSubscriptions(subscriptionDir, activeTags); err != nil {
		return nil, err
	}
	if len(descriptors) == 0 {
		if resolvingFailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}
	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}
	log.WithFields(log.Fields{
		"duration": time.Since(started),
		"nodes":    len(descriptors),
	}).Info("Prepared nodes")
	return descriptors, nil
}

// Local subscription sources are configuration inputs; only downloaded
// subscription state belongs in the unified cache directory.
func subscriptionSourceDirectory(link, configDir string) string {
	_, raw := resource.Split(link)
	source, err := resource.Parse(raw, configDir)
	if err == nil && !source.Remote() {
		return configDir
	}
	return cacheDirectory()
}

func persistentSubscriptionTags(subscriptions []config.Subscription) (map[string]struct{}, error) {
	tags := make(map[string]struct{}, len(subscriptions))
	for _, sub := range subscriptions {
		tag, ok := subscription.PersistentTag(sub.String())
		if !ok {
			continue
		}
		if _, exists := tags[tag]; exists {
			return nil, fmt.Errorf("duplicate persistent subscription tag %q", tag)
		}
		tags[tag] = struct{}{}
	}
	return tags, nil
}
